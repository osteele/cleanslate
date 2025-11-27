//! Project discovery and artifact scanning.

use crate::patterns::{is_artifact, is_project_root, is_recreatable_dir, ArtifactPattern};
use crate::time::{TimeFilter, TimeFilterContext, TimeFilterStats};
use crate::vcs::{
    detect_vcs, get_tracked_files_batch, has_tracked_files, is_tracked_in_vcs, VcsCheckResult,
    VCS_INTERNALS,
};

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
    pub delete: bool,
    pub verbose: bool,
    pub dry_run: bool,
    pub list: bool,
    pub calculate_sizes: bool,
}

/// An artifact entry found during scanning
pub struct ArtifactEntry {
    pub path: PathBuf,
    pub size: u64,
    pub removed: bool,
    #[allow(dead_code)]
    pub modified: Option<SystemTime>,
    pub time_filtered: bool,
}

/// Report of artifacts found in a project
pub struct ProjectReport {
    pub artifacts: Vec<ArtifactEntry>,
}

/// Result from scanning a single path
pub struct ScanResult {
    pub projects: HashMap<PathBuf, ProjectReport>,
    pub total_bytes: u64,
    pub stats: TimeFilterStats,
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
    let indicators = [
        "Cargo.toml",     // Rust
        "pyproject.toml", // Python
        "package.json",   // JavaScript/Node
        "go.mod",         // Go
        ".git",           // Generic project indicator
    ];

    // Start from the parent if path is a file
    let mut current = if path.is_file() {
        path.parent()
    } else {
        Some(path)
    };

    while let Some(p) = current {
        for indicator in &indicators {
            if p.join(indicator).exists() {
                return Some(p.to_path_buf());
            }
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

/// Handle a directory artifact (Category 2 or Category 3)
fn handle_directory_artifact(
    path: &Path,
    start_path: &Path,
    project_root: &Path,
    projects: &mut HashMap<PathBuf, ProjectReport>,
    skip_paths: &Arc<Mutex<HashSet<PathBuf>>>,
    options: ScanOptions,
    time_ctx: &mut TimeFilterContext,
) -> Result<u64> {
    let mut total_bytes = 0u64;

    time_ctx.stats.total_found += 1;

    // Detect VCS type once for this directory
    let (vcs_type, vcs_root) = detect_vcs(path);
    let vcs_root = vcs_root.unwrap_or_else(|| start_path.to_path_buf());

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

    if passes_time_filter {
        time_ctx.stats.passed_time_filter += 1;
    } else {
        time_ctx.stats.excluded_by_time += 1;
        if options.verbose {
            println!("Directory filtered by time: {}", path.display());
        }
    }

    // Category 2: Recreatable directories (spot-check)
    if is_recreatable_dir(path) {
        if options.verbose {
            println!(
                "DEBUG: Spot-checking Category 2 directory: {}",
                path.display()
            );
        }

        // Spot-check: Does this directory contain ANY tracked files?
        match has_tracked_files(path, vcs_type, &vcs_root) {
            Some(true) => {
                if options.verbose {
                    println!("  Contains tracked files, skipping");
                }
                skip_paths.lock().unwrap().insert(path.to_path_buf());
                return Ok(0);
            }
            None => {
                // VCS check failed - skip removal to be safe
                if options.verbose {
                    eprintln!(
                        "Warning: VCS check failed for {}, skipping to be safe",
                        path.display()
                    );
                }
                skip_paths.lock().unwrap().insert(path.to_path_buf());
                return Ok(0);
            }
            Some(false) => {
                // No tracked files, continue with removal
            }
        }

        // No tracked files → entire directory can be removed
        // Skip size calculation unless explicitly requested
        let dir_size = if options.calculate_sizes {
            calculate_total_dir_size(path)
        } else {
            0 // Size not calculated
        };

        // Only count towards total if it passes time filter
        if passes_time_filter {
            total_bytes += dir_size;
        }

        let project_report = projects
            .entry(project_root.to_path_buf())
            .or_insert_with(|| ProjectReport {
                artifacts: Vec::new(),
            });

        // Remove entire directory if in delete mode AND passes time filter
        let should_remove = passes_time_filter && (options.delete || options.dry_run);
        if should_remove && options.delete && !options.dry_run {
            match fs::remove_dir_all(path) {
                Ok(_) => {
                    if options.verbose {
                        println!("Removed directory: {}", path.display());
                    }
                }
                Err(err) => {
                    if options.verbose {
                        eprintln!("Error removing {}: {}", path.display(), err);
                    }
                }
            }
        } else if should_remove && options.dry_run && options.list {
            println!("Would remove directory: {}", path.display());
        }

        let dir_modified = fs::symlink_metadata(path)
            .ok()
            .and_then(|m| m.modified().ok());

        project_report.artifacts.push(ArtifactEntry {
            path: path.to_path_buf(),
            size: dir_size,
            removed: should_remove,
            modified: dir_modified,
            time_filtered: !passes_time_filter,
        });

        skip_paths.lock().unwrap().insert(path.to_path_buf());
        return Ok(total_bytes);
    }

    // Category 3: Other directories (batch-check contents)
    if options.verbose {
        println!(
            "DEBUG: Batch-checking Category 3 directory: {}",
            path.display()
        );
    }

    // Get all tracked files in this directory with a single VCS call
    let tracked_files = match get_tracked_files_batch(path, vcs_type, &vcs_root) {
        Ok(files) => files,
        Err(e) => {
            // VCS check failed - skip this directory to be safe
            if options.verbose {
                eprintln!(
                    "Warning: VCS check failed for {}: {}, skipping to be safe",
                    path.display(),
                    e
                );
            }
            skip_paths.lock().unwrap().insert(path.to_path_buf());
            return Ok(0);
        }
    };

    if options.verbose {
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

            // Only add to removal list if it passes time filter
            if file_passes_time_filter {
                let file_size = if options.calculate_sizes {
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

    // Only report and remove if there are untracked files
    if !files_to_remove.is_empty() {
        // For Category 3: files are already filtered by mtime, so add size unconditionally
        total_bytes += dir_total_size;

        let project_report = projects
            .entry(project_root.to_path_buf())
            .or_insert_with(|| ProjectReport {
                artifacts: Vec::new(),
            });

        // Remove files if in delete mode (files already passed time filter check)
        let should_remove = options.delete || options.dry_run;
        if should_remove && options.delete && !options.dry_run {
            for (file_path, _) in &files_to_remove {
                match fs::remove_file(file_path) {
                    Ok(_) => {
                        if options.verbose {
                            println!("Removed: {}", file_path.display());
                        }
                    }
                    Err(err) => {
                        if options.verbose {
                            eprintln!("Error removing {}: {}", file_path.display(), err);
                        }
                    }
                }
            }
        } else if should_remove && options.dry_run && options.list {
            println!(
                "Would remove: {} ({} untracked files)",
                path.display(),
                files_to_remove.len()
            );
        }

        let dir_modified = fs::symlink_metadata(path)
            .ok()
            .and_then(|m| m.modified().ok());

        // Category 3: Files already filtered, so time_filtered is always false for reported artifacts
        project_report.artifacts.push(ArtifactEntry {
            path: path.to_path_buf(),
            size: dir_total_size,
            removed: should_remove,
            modified: dir_modified,
            time_filtered: false, // Files already passed time filter check
        });
    }

    skip_paths.lock().unwrap().insert(path.to_path_buf());
    Ok(total_bytes)
}

/// Handle a file artifact
fn handle_file_artifact(
    path: &Path,
    metadata: &fs::Metadata,
    project_root: &Path,
    projects: &mut HashMap<PathBuf, ProjectReport>,
    options: ScanOptions,
    time_ctx: &mut TimeFilterContext,
) -> Result<u64> {
    time_ctx.stats.total_found += 1;

    // For files: check if tracked in version control
    match is_tracked_in_vcs(path) {
        VcsCheckResult::Tracked => {
            if options.verbose {
                println!("Skipping tracked file: {}", path.display());
            }
            return Ok(0);
        }
        VcsCheckResult::Unknown(e) => {
            // VCS check failed - skip removal to be safe
            if options.verbose {
                eprintln!(
                    "Warning: VCS check failed for {}: {}, skipping to be safe",
                    path.display(),
                    e
                );
            }
            return Ok(0);
        }
        VcsCheckResult::Untracked => {
            // Continue with removal
        }
    }

    // Extract modification time
    let modified_time = metadata.modified().ok();

    // Check time filter if active
    let passes_time_filter = if time_ctx.filter.is_active() {
        if let Some(mtime) = modified_time {
            time_ctx.filter.passes(mtime)
        } else {
            if options.verbose {
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
        if options.verbose {
            println!("File filtered by time: {}", path.display());
        }
    }

    let size = metadata.len();

    let project_report = projects
        .entry(project_root.to_path_buf())
        .or_insert_with(|| ProjectReport {
            artifacts: Vec::new(),
        });

    // Only remove if passes time filter
    let should_remove = passes_time_filter && (options.delete || options.dry_run);
    let removed = if should_remove {
        if options.dry_run {
            if options.list {
                println!("Would remove: {}", path.display());
            }
            false // Not actually removed in dry run
        } else {
            // We only remove files now, directories are handled in cleanup pass
            match fs::remove_file(path) {
                Ok(_) => {
                    if options.verbose {
                        println!("Removed: {}", path.display());
                    }
                    true
                }
                Err(err) => {
                    eprintln!("Error removing {}: {}. Skipping.", path.display(), err);
                    false
                }
            }
        }
    } else {
        false // Not removed if doesn't pass time filter or neither delete nor dry_run
    };

    project_report.artifacts.push(ArtifactEntry {
        path: path.to_path_buf(),
        size,
        removed,
        modified: modified_time,
        time_filtered: !passes_time_filter,
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
    let mut stats = TimeFilterStats::default();

    // Canonicalize the project root
    let project_root = project_root.canonicalize().unwrap_or(project_root);

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

        // Check if the path is an artifact
        if is_artifact(path, patterns) {
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
                let bytes = handle_directory_artifact(
                    path,
                    &project_root,
                    &project_root,
                    &mut projects,
                    &skip_paths,
                    options,
                    &mut time_ctx,
                )?;
                total_bytes += bytes;
            } else {
                let bytes = handle_file_artifact(
                    path,
                    &metadata,
                    &project_root,
                    &mut projects,
                    options,
                    &mut time_ctx,
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
    let mut stats = TimeFilterStats::default();

    for result in results {
        total_bytes += result.total_bytes;
        stats.total_found += result.stats.total_found;
        stats.passed_time_filter += result.stats.passed_time_filter;
        stats.excluded_by_time += result.stats.excluded_by_time;

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
    if name.len() <= max_width {
        name.to_string()
    } else if max_width >= 3 {
        let truncate_to = max_width.saturating_sub(3);
        format!("{}...", &name[..truncate_to])
    } else {
        "...".to_string()
    }
}
