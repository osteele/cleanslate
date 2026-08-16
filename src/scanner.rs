//! Project discovery and artifact scanning. Scanning is pure: it never deletes.

use crate::patterns::{
    is_project_root, is_recreatable_dir, matching_pattern, ArtifactPattern, ArtifactType,
};
use crate::time::TimeFilter;
use crate::vcs::{detect_vcs, get_tracked_files_batch, VcsMetrics, VcsType, VCS_INTERNALS};

use anyhow::Result;
use crossbeam_channel::{bounded, Sender};
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::SystemTime;

/// Options controlling scan behavior (runtime flags)
#[derive(Clone, Copy)]
pub struct ScanOptions {
    pub verbose: bool,
    pub calculate_sizes: bool,
}

/// Statistics gathered during a scan
#[derive(Debug, Default)]
pub struct ScanStats {
    pub total_found: usize,
    pub passed_time_filter: usize,
    pub excluded_by_time: usize,
    /// Paths skipped because their VCS tracking status could not be determined
    pub vcs_check_failures: usize,
    /// Number of batch VCS calls issued during the scan.
    pub vcs_batch_call_count: usize,
}

/// Context for time-based filtering, including the filter and scan statistics
pub struct TimeFilterContext<'a> {
    pub filter: &'a TimeFilter,
    pub stats: &'a mut ScanStats,
}

/// An artifact entry found during scanning
pub struct ArtifactEntry {
    pub path: PathBuf,
    pub size: u64,
    pub removed: bool,
    pub modified: Option<SystemTime>,
    pub time_filtered: bool,
    /// Language name from the pattern that matched this artifact (e.g., "Python")
    pub language_name: String,
    /// Artifact type from the pattern that matched this artifact
    pub artifact_type: ArtifactType,
    /// Files to remove for Category 3 (mixed) directories; empty for Category 2 dirs and files.
    pub files: Vec<PathBuf>,
}

/// Report of artifacts found in a project
pub struct ProjectReport {
    pub artifacts: Vec<ArtifactEntry>,
}

/// Result from scanning a single path
pub struct ScanResult {
    pub projects: HashMap<PathBuf, ProjectReport>,
    pub total_bytes: u64,
    pub stats: ScanStats,
}

/// Calculate total size of a directory (all files, not just artifacts)
fn calculate_total_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            // Use symlink_metadata instead of entry.metadata() to avoid following symlinks
            // This is equivalent to Python's os.stat(follow_symlinks=False) and prevents
            // triggering iCloud materialization
            if let Ok(metadata) = fs::symlink_metadata(&entry_path) {
                if metadata.is_file() {
                    total += metadata.len();
                } else if metadata.is_dir() {
                    // Skip VCS directories
                    if let Some(name) = entry_path.file_name() {
                        if VCS_INTERNALS.contains(&name.to_str().unwrap_or("")) {
                            continue;
                        }
                    }
                    total += calculate_total_dir_size(&entry_path);
                }
            }
        }
    }

    total
}

/// Return whether an artifact directory contains a nested VCS checkout.
/// Refuse wholesale cleanup when repository metadata appears anywhere below it.
fn contains_vcs_checkout(path: &Path) -> Result<bool> {
    for entry in walkdir::WalkDir::new(path).min_depth(1).follow_links(false) {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| VCS_INTERNALS.contains(&name))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if a path should be excluded based on directory name matching
pub fn should_exclude_path(path: &Path, excludes: &[String]) -> bool {
    if excludes.is_empty() {
        return false;
    }

    // Check each component of the path
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let dir_name = name.to_string_lossy();
            if excludes.iter().any(|exclude| exclude == dir_name.as_ref()) {
                return true;
            }
        }
    }

    false
}

/// Find the project root for a given path
pub fn find_project_root(path: &Path) -> Option<PathBuf> {
    // Start from the parent if path is a file
    let mut current = if path.is_file() {
        path.parent()
    } else {
        Some(path)
    };

    while let Some(p) = current {
        if crate::patterns::is_project_root(p) {
            return Some(p.to_path_buf());
        }

        current = p.parent();
    }

    // If we couldn't determine a project root, return the parent directory
    // Never return a file path as a project root
    if path.is_file() {
        path.parent().map(|p| p.to_path_buf())
    } else {
        Some(path.to_path_buf())
    }
}

/// VCS state for a single project, computed once before traversal.
enum ProjectVcsState {
    /// No VCS detected; all artifacts are treated as untracked.
    NoVcs,
    /// VCS detected and the full tracked-file set was fetched successfully.
    Tracked { tracked_files: HashSet<PathBuf> },
    /// The project-level VCS call failed; every artifact must be skipped to be safe.
    Failed { message: String },
}

/// Values invariant for the duration of a single project's scan.
struct ArtifactScan<'a> {
    project_root: &'a Path,
    skip_paths: &'a Arc<Mutex<HashSet<PathBuf>>>,
    options: ScanOptions,
    vcs_state: &'a ProjectVcsState,
}

/// Handle a directory artifact (Category 2 or Category 3)
fn handle_directory_artifact(
    path: &Path,
    pattern: &ArtifactPattern,
    projects: &mut HashMap<PathBuf, ProjectReport>,
    time_ctx: &mut TimeFilterContext,
    scan: &ArtifactScan,
) -> Result<u64> {
    let mut total_bytes = 0u64;

    match contains_vcs_checkout(path) {
        Ok(true) => {
            if scan.options.verbose {
                println!(
                    "Directory contains nested version-control metadata, skipping: {}",
                    path.display()
                );
            }
            scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
            return Ok(0);
        }
        Err(error) => {
            time_ctx.stats.vcs_check_failures += 1;
            if scan.options.verbose {
                eprintln!(
                    "Warning: Could not inspect {} for nested repositories: {}, skipping to be safe",
                    path.display(),
                    error
                );
            }
            scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
            return Ok(0);
        }
        Ok(false) => {}
    }

    // Category 2: Recreatable directories (spot-check)
    if is_recreatable_dir(path) {
        if scan.options.verbose {
            println!(
                "DEBUG: Spot-checking Category 2 directory: {}",
                path.display()
            );
        }

        // Spot-check: Does this directory contain ANY tracked files?
        let has_tracked = match scan.vcs_state {
            ProjectVcsState::Failed { .. } => {
                // VCS check failed - skip removal to be safe
                time_ctx.stats.vcs_check_failures += 1;
                if scan.options.verbose {
                    eprintln!(
                        "Warning: VCS check failed for {}, skipping to be safe",
                        path.display()
                    );
                }
                scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
                return Ok(0);
            }
            ProjectVcsState::NoVcs => false,
            ProjectVcsState::Tracked { tracked_files, .. } => {
                tracked_files.iter().any(|f| f.starts_with(path))
            }
        };

        if has_tracked {
            if scan.options.verbose {
                println!("  Contains tracked files, skipping");
            }
            scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
            return Ok(0);
        }

        // Check time filter for directories (using directory's own modification time)
        let passes_time_filter = if time_ctx.filter.is_active() {
            if let Ok(metadata) = fs::symlink_metadata(path) {
                if let Ok(mtime) = metadata.modified() {
                    time_ctx.filter.passes(mtime)
                } else {
                    true // If we can't get mtime, assume it passes
                }
            } else {
                true // If we can't get metadata, assume it passes
            }
        } else {
            true // No time filter active
        };

        // This directory is a candidate for removal.
        time_ctx.stats.total_found += 1;
        if passes_time_filter {
            time_ctx.stats.passed_time_filter += 1;
        } else {
            time_ctx.stats.excluded_by_time += 1;
            if scan.options.verbose {
                println!("Directory filtered by time: {}", path.display());
            }
        }

        // No tracked files → entire directory can be removed
        // Skip size calculation unless explicitly requested
        let dir_size = if scan.options.calculate_sizes {
            calculate_total_dir_size(path)
        } else {
            0 // Size not calculated
        };

        // Only count towards total if it passes time filter
        if passes_time_filter {
            total_bytes += dir_size;
        }

        let project_report = projects
            .entry(scan.project_root.to_path_buf())
            .or_insert_with(|| ProjectReport {
                artifacts: Vec::new(),
            });

        let dir_modified = fs::symlink_metadata(path)
            .ok()
            .and_then(|m| m.modified().ok());

        project_report.artifacts.push(ArtifactEntry {
            path: path.to_path_buf(),
            size: dir_size,
            removed: false,
            modified: dir_modified,
            time_filtered: !passes_time_filter,
            language_name: pattern.language_name.clone(),
            artifact_type: pattern.artifact_type,
            files: Vec::new(),
        });

        scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
        return Ok(total_bytes);
    }

    // Category 3: Other directories (batch-check contents)
    if scan.options.verbose {
        println!(
            "DEBUG: Batch-checking Category 3 directory: {}",
            path.display()
        );
    }

    // Get all tracked files in this directory from the cached project set.
    let tracked_files: HashSet<PathBuf> = match scan.vcs_state {
        ProjectVcsState::Failed { .. } => {
            time_ctx.stats.vcs_check_failures += 1;
            if scan.options.verbose {
                eprintln!(
                    "Warning: VCS check failed for {}, skipping to be safe",
                    path.display()
                );
            }
            scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
            return Ok(0);
        }
        ProjectVcsState::NoVcs => HashSet::new(),
        ProjectVcsState::Tracked { tracked_files, .. } => tracked_files
            .iter()
            .filter(|f| f.starts_with(path))
            .cloned()
            .collect(),
    };

    if scan.options.verbose {
        println!("  Found {} tracked files", tracked_files.len());
    }

    // Walk directory and collect untracked files for removal
    let mut dir_total_size = 0u64;
    let mut files_to_remove = Vec::new();

    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let file_path = entry.path();

        // Check if file is tracked (O(1) lookup in HashSet)
        if !tracked_files.contains(file_path) {
            // Category 3: Check each file's mtime individually
            let file_passes_time_filter = if time_ctx.filter.is_active() {
                if let Ok(meta) = fs::symlink_metadata(file_path) {
                    if let Ok(mtime) = meta.modified() {
                        time_ctx.filter.passes(mtime)
                    } else {
                        true // If we can't get mtime, assume it passes
                    }
                } else {
                    true // If we can't get metadata, assume it passes
                }
            } else {
                true // No time filter active
            };

            // Each untracked file is a candidate for removal.
            time_ctx.stats.total_found += 1;
            if file_passes_time_filter {
                time_ctx.stats.passed_time_filter += 1;
            } else {
                time_ctx.stats.excluded_by_time += 1;
                if scan.options.verbose {
                    println!("File filtered by time: {}", file_path.display());
                }
            }

            // Only add to removal list if it passes time filter
            if file_passes_time_filter {
                let file_size = if scan.options.calculate_sizes {
                    // Use symlink_metadata to avoid following symlinks (same as Python's lstat)
                    if let Ok(meta) = fs::symlink_metadata(file_path) {
                        let size = meta.len();
                        dir_total_size += size;
                        size
                    } else {
                        0
                    }
                } else {
                    0 // Size not calculated
                };
                files_to_remove.push((file_path.to_path_buf(), file_size));
            }
        }
    }

    // Only report if there are untracked files that pass the time filter
    if !files_to_remove.is_empty() {
        // For Category 3: files are already filtered by mtime, so add size unconditionally
        total_bytes += dir_total_size;

        let project_report = projects
            .entry(scan.project_root.to_path_buf())
            .or_insert_with(|| ProjectReport {
                artifacts: Vec::new(),
            });

        let file_paths: Vec<PathBuf> = files_to_remove.iter().map(|(p, _)| p.clone()).collect();

        let dir_modified = fs::symlink_metadata(path)
            .ok()
            .and_then(|m| m.modified().ok());

        // Category 3: Files already filtered, so time_filtered is always false for reported artifacts
        project_report.artifacts.push(ArtifactEntry {
            path: path.to_path_buf(),
            size: dir_total_size,
            removed: false,
            modified: dir_modified,
            time_filtered: false, // Files already passed time filter check
            language_name: pattern.language_name.clone(),
            artifact_type: pattern.artifact_type,
            files: file_paths,
        });
    }

    scan.skip_paths.lock().unwrap().insert(path.to_path_buf());
    Ok(total_bytes)
}

/// Handle a file artifact
fn handle_file_artifact(
    path: &Path,
    metadata: &fs::Metadata,
    pattern: &ArtifactPattern,
    projects: &mut HashMap<PathBuf, ProjectReport>,
    time_ctx: &mut TimeFilterContext,
    scan: &ArtifactScan,
) -> Result<u64> {
    // For files: check if tracked in version control using the cached project set.
    match scan.vcs_state {
        ProjectVcsState::Failed { message } => {
            // VCS check failed - skip removal to be safe
            time_ctx.stats.vcs_check_failures += 1;
            if scan.options.verbose {
                eprintln!(
                    "Warning: VCS check failed for {}: {}, skipping to be safe",
                    path.display(),
                    message
                );
            }
            return Ok(0);
        }
        ProjectVcsState::Tracked { tracked_files, .. } if tracked_files.contains(path) => {
            if scan.options.verbose {
                println!("Skipping tracked file: {}", path.display());
            }
            return Ok(0);
        }
        ProjectVcsState::NoVcs | ProjectVcsState::Tracked { .. } => {
            // Untracked: continue with removal
        }
    }

    // This file is a candidate for removal.
    time_ctx.stats.total_found += 1;

    // Extract modification time
    let modified_time = metadata.modified().ok();

    // Check time filter if active
    let passes_time_filter = if time_ctx.filter.is_active() {
        if let Some(mtime) = modified_time {
            time_ctx.filter.passes(mtime)
        } else {
            if scan.options.verbose {
                println!(
                    "Warning: Could not get modification time for {}",
                    path.display()
                );
            }
            true // If we can't get mtime, assume it passes
        }
    } else {
        true // No time filter active
    };

    if passes_time_filter {
        time_ctx.stats.passed_time_filter += 1;
    } else {
        time_ctx.stats.excluded_by_time += 1;
        if scan.options.verbose {
            println!("File filtered by time: {}", path.display());
        }
    }

    let size = metadata.len();

    let project_report = projects
        .entry(scan.project_root.to_path_buf())
        .or_insert_with(|| ProjectReport {
            artifacts: Vec::new(),
        });

    project_report.artifacts.push(ArtifactEntry {
        path: path.to_path_buf(),
        size,
        removed: false,
        modified: modified_time,
        time_filtered: !passes_time_filter,
        language_name: pattern.language_name.clone(),
        artifact_type: pattern.artifact_type,
        files: Vec::new(),
    });

    // Only count towards total if it passes time filter
    Ok(if passes_time_filter { size } else { 0 })
}

/// Discover project directories and send them to a channel for parallel processing.
/// This function walks the directory tree and identifies project roots. Once a project root
/// is found, it sends it to the channel and doesn't descend into that project's subdirectories.
fn discover_projects_streaming(
    start_path: &Path,
    _patterns: &[ArtifactPattern],
    exclude: &[String],
    sender: Sender<PathBuf>,
    progress: Arc<ProgressBar>,
) -> Result<()> {
    // Special case: if start_path itself is a project root, just send it
    if is_project_root(start_path) {
        sender.send(start_path.to_path_buf()).ok();
        progress.set_message("Discovery complete: found 1 project".to_string());
        return Ok(());
    }

    let discovered_count = Arc::new(Mutex::new(0u64));
    let discovered_count_clone = Arc::clone(&discovered_count);
    let discovered_projects = Arc::new(Mutex::new(HashSet::new()));
    let discovered_projects_clone = Arc::clone(&discovered_projects);
    let entries_scanned = Arc::new(Mutex::new(0u64));
    let entries_scanned_clone = Arc::clone(&entries_scanned);
    let progress_clone = Arc::clone(&progress);
    let exclude_clone = exclude.to_vec();
    let start_path_buf = start_path.to_path_buf();

    let walker = WalkBuilder::new(start_path)
        .hidden(false)
        // Disable gitignore processing - it adds significant overhead (parsing hundreds of
        // .gitignore files) with no benefit since:
        // 1. We have our own artifact patterns in artifacts.toml
        // 2. We already skip VCS directories via VCS_INTERNALS
        // 3. We use VCS commands (git ls-files/jj file list) as source of truth for tracking
        .git_ignore(false)
        .ignore(false)
        .git_global(false)
        .git_exclude(false)
        .filter_entry(move |entry| {
            let path = entry.path();

            // Update progress
            {
                let mut count = entries_scanned_clone.lock().unwrap();
                *count += 1;
                if *count % 100 == 0 {
                    progress_clone
                        .set_message(format!("Discovering projects: {} entries scanned", count));
                }
            }

            // Never traverse VCS internals
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if VCS_INTERNALS.contains(&name) {
                    return false;
                }
            }

            // Skip user-excluded directories
            if entry.file_type().is_some_and(|ft| ft.is_dir()) {
                if should_exclude_path(path, &exclude_clone) {
                    return false;
                }

                // Don't descend into subdirectories of discovered project roots
                if path != start_path_buf {
                    let projects = discovered_projects_clone.lock().unwrap();
                    if projects.iter().any(|proj: &PathBuf| path.starts_with(proj)) {
                        return false;
                    }
                }

                // Check if this directory IS a project root
                if is_project_root(path) {
                    // Mark it as discovered to prevent descending into subdirectories
                    discovered_projects_clone
                        .lock()
                        .unwrap()
                        .insert(path.to_path_buf());
                    *discovered_count_clone.lock().unwrap() += 1;
                    // Note: We still return true to allow the walker to yield this entry
                    // so we can send it in the main loop
                }
            }

            true
        })
        .build();

    for result in walker {
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!("Warning: Failed to access entry during discovery: {}", err);
                continue;
            }
        };

        let path = entry.path();

        // Check if this was marked as a project root (already added to discovered_projects in filter_entry)
        if discovered_projects.lock().unwrap().contains(path)
            && sender.send(path.to_path_buf()).is_err()
        {
            // Receiver dropped, stop discovering
            break;
        }
    }

    let count = *discovered_count.lock().unwrap();
    if count == 0 {
        // Fallback: scan start_path itself when no projects discovered
        // This handles directories with artifacts but no project markers
        sender.send(start_path.to_path_buf()).ok();
        progress.set_message("No projects found, scanning directory directly...".to_string());
    } else {
        progress.set_message(format!(
            "Discovered {} projects, scanning artifacts...",
            count
        ));
    }
    Ok(())
}

/// Scan a single project for artifacts.
/// This is extracted from scan_single_path to allow parallel processing at the project level.
fn scan_project_for_artifacts(
    project_root: PathBuf,
    patterns: &[ArtifactPattern],
    exclude: &[String],
    options: ScanOptions,
    time_filter: &TimeFilter,
) -> Result<ScanResult> {
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let skip_paths = Arc::new(Mutex::new(HashSet::<PathBuf>::new()));
    let mut total_bytes: u64 = 0;
    let mut stats = ScanStats::default();

    // Canonicalize the project root
    let project_root = project_root.canonicalize().unwrap_or(project_root);

    // Detect VCS once for the project and fetch the full tracked-file set once.
    let metrics = VcsMetrics::new();
    let (vcs_type, vcs_root) = detect_vcs(&project_root);
    let vcs_root = vcs_root.unwrap_or_else(|| project_root.to_path_buf());
    let vcs_state: ProjectVcsState = if vcs_type == VcsType::None {
        ProjectVcsState::NoVcs
    } else {
        match get_tracked_files_batch(&project_root, vcs_type, &vcs_root, &metrics) {
            Ok(tracked_files) => ProjectVcsState::Tracked { tracked_files },
            Err(message) => ProjectVcsState::Failed { message },
        }
    };
    stats.vcs_batch_call_count = metrics.batch_call_count();

    let scan = ArtifactScan {
        project_root: &project_root,
        skip_paths: &skip_paths,
        options,
        vcs_state: &vcs_state,
    };

    let exclude_clone = exclude.to_vec();

    let walker = WalkBuilder::new(&project_root)
        .hidden(false)
        // Disable gitignore processing - adds overhead with no benefit (see comment in discover_projects_streaming)
        .git_ignore(false)
        .ignore(false)
        .git_global(false)
        .git_exclude(false)
        .filter_entry(move |entry| {
            let path = entry.path();

            // Never traverse VCS internals
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if VCS_INTERNALS.contains(&name) {
                    return false;
                }
            }

            // Skip user-excluded directories
            if entry.file_type().is_some_and(|ft| ft.is_dir())
                && should_exclude_path(path, &exclude_clone)
            {
                return false;
            }

            true
        })
        .build();

    for result in walker {
        let entry = match result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!(
                    "Warning: Failed to access entry in {}: {}",
                    project_root.display(),
                    err
                );
                continue;
            }
        };

        let path = entry.path();

        // Never process the project root itself as an artifact
        if path == project_root.as_path() {
            continue;
        }

        // Skip if this path is inside an artifact directory we've already processed
        {
            let skip_paths_set = skip_paths.lock().unwrap();
            if skip_paths_set.iter().any(|skip| path.starts_with(skip)) {
                continue;
            }
        }

        // Check if the path is an artifact, and which pattern matched it
        if let Some(pattern) = matching_pattern(path, patterns) {
            let metadata = match fs::symlink_metadata(path) {
                Ok(meta) => meta,
                Err(err) => {
                    eprintln!(
                        "Warning: Could not get metadata for {}: {}",
                        path.display(),
                        err
                    );
                    continue;
                }
            };

            // Skip symlinks
            if metadata.is_symlink() {
                if options.verbose {
                    println!("Skipping symlink: {}", path.display());
                }
                continue;
            }

            // Handle directories or files
            let mut time_ctx = TimeFilterContext {
                filter: time_filter,
                stats: &mut stats,
            };
            if metadata.is_dir() {
                let bytes =
                    handle_directory_artifact(path, pattern, &mut projects, &mut time_ctx, &scan)?;
                total_bytes += bytes;
            } else {
                let bytes = handle_file_artifact(
                    path,
                    &metadata,
                    pattern,
                    &mut projects,
                    &mut time_ctx,
                    &scan,
                )?;
                total_bytes += bytes;
            }
        }
    }

    Ok(ScanResult {
        projects,
        total_bytes,
        stats,
    })
}

/// Scan a single path for artifacts using streaming producer-consumer architecture.
/// This parallelizes at the repository level for much better performance when scanning
/// directories containing many projects.
pub fn scan_single_path(
    start_path_str: &str,
    patterns: &[ArtifactPattern],
    exclude: &[String],
    options: ScanOptions,
    time_filter: &TimeFilter,
) -> Result<ScanResult> {
    let start_path = PathBuf::from(start_path_str);

    if options.verbose {
        println!("DEBUG: Scanning directory {}", start_path.display());
    }

    // Create progress bar
    let progress = Arc::new(ProgressBar::new_spinner());
    progress.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    progress.enable_steady_tick(std::time::Duration::from_millis(100));

    // Create bounded channel for streaming project roots
    let (sender, receiver) = bounded::<PathBuf>(100);

    // Clone data for producer thread
    let patterns_clone = patterns.to_vec();
    let exclude_clone = exclude.to_vec();
    let start_path_clone = start_path.clone();
    let progress_clone = Arc::clone(&progress);

    // Spawn producer thread to discover projects
    let producer_handle = thread::spawn(move || {
        discover_projects_streaming(
            &start_path_clone,
            &patterns_clone,
            &exclude_clone,
            sender,
            progress_clone,
        )
    });

    // Process discovered projects in parallel using rayon
    let results: Vec<ScanResult> = receiver
        .into_iter()
        .par_bridge()
        .map(|project_root| {
            scan_project_for_artifacts(project_root, patterns, exclude, options, time_filter)
        })
        .collect::<Result<Vec<_>>>()?;

    // Wait for producer to finish
    producer_handle
        .join()
        .map_err(|_| anyhow::anyhow!("Producer thread panicked"))??;

    // Merge results from parallel processing
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let mut total_bytes: u64 = 0;
    let mut stats = ScanStats::default();

    for result in results {
        total_bytes += result.total_bytes;
        stats.total_found += result.stats.total_found;
        stats.passed_time_filter += result.stats.passed_time_filter;
        stats.excluded_by_time += result.stats.excluded_by_time;
        stats.vcs_check_failures += result.stats.vcs_check_failures;
        stats.vcs_batch_call_count += result.stats.vcs_batch_call_count;

        for (project_path, project_report) in result.projects {
            projects
                .entry(project_path)
                .or_insert_with(|| ProjectReport {
                    artifacts: Vec::new(),
                })
                .artifacts
                .extend(project_report.artifacts);
        }
    }

    // Finish progress bar
    progress.finish_with_message("Scan complete!");

    Ok(ScanResult {
        projects,
        total_bytes,
        stats,
    })
}

/// Truncate an artifact name with "..." suffix if it exceeds max_width
pub fn truncate_name_with_suffix(name: &str, max_width: usize) -> String {
    let character_count = name.chars().count();
    if character_count <= max_width {
        name.to_string()
    } else if max_width >= 3 {
        let truncate_to = max_width.saturating_sub(3);
        format!("{}...", name.chars().take(truncate_to).collect::<String>())
    } else {
        "...".to_string()
    }
}
