use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use humansize::{format_size, BINARY};
use ignore::WalkBuilder;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Find and optionally clean build artifacts and caches from various programming languages",
    long_about = None
)]
struct Args {
    /// Directories to scan (defaults to current directory)
    #[arg(default_values_t = vec![String::from(".")])]
    paths: Vec<String>,

    /// Delete the found artifacts
    #[arg(long, short)]
    delete: bool,

    /// Show detailed information about found artifacts
    #[arg(long, short)]
    verbose: bool,

    /// Show individual files instead of summary per directory
    #[arg(long, short)]
    files: bool,

    /// Show what would be deleted without actually deleting (implies --delete)
    #[arg(long)]
    dry_run: bool,

    /// Show detailed list format instead of table (table is default)
    #[arg(long, short)]
    list: bool,

    /// Aggressive mode: also remove small/trivial files like .DS_Store
    #[arg(long)]
    aggressive: bool,
}

struct ArtifactEntry {
    path: PathBuf,
    size: u64,
    removed: bool,
}

struct ProjectReport {
    artifacts: Vec<ArtifactEntry>,
}

/// Define artifact types for better classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactType {
    Cache,        // Cache directories that are safe to delete
    Dependency,   // Dependency directories (node_modules, etc.)
    Build,        // Build artifacts (dist, build, etc.)
    Temp,         // Temporary files (.DS_Store, etc.)
    Logs,         // Log files
    Intermediate, // Intermediate files (*.pyc, etc.)
    IDE,          // IDE files (.vscode, .idea, etc.)
}

/// Structure to hold artifact pattern and its type
#[derive(Debug, Clone)]
pub struct ArtifactPattern {
    pattern: String,
    #[allow(dead_code)]
    artifact_type: ArtifactType,
    /// Is this a standalone pattern or should it be properly contextualized?
    /// For example, "dist" should only match at the project root level, not any directory named "dist"
    needs_context: bool,
    /// The name of the language this pattern belongs to (e.g., "Python", "JavaScript")
    language_name: String,
    /// Whether this pattern should only be used in aggressive mode
    aggressive: bool,
}

/// Structure to deserialize artifact patterns from TOML
#[derive(Debug, Deserialize)]
struct ArtifactConfig {
    #[serde(flatten)]
    languages: HashMap<String, LanguageConfig>,
}

#[derive(Debug, Deserialize)]
struct LanguageConfig {
    name: String,
    #[serde(flatten)]
    types: HashMap<String, PatternConfig>,
}

#[derive(Debug, Deserialize)]
struct PatternConfig {
    patterns: Vec<String>,
    #[serde(default)]
    aggressive: bool,
}

// Embed the TOML file directly in the binary at compile time
const ARTIFACTS_TOML: &str = include_str!("../artifacts.toml");

/// Parse artifact patterns from the embedded TOML content
fn get_artifact_patterns_from_toml() -> Result<Vec<ArtifactPattern>> {
    // Parse the TOML content
    let config: ArtifactConfig =
        toml::from_str(ARTIFACTS_TOML).context("Failed to parse artifacts TOML file")?;

    let mut patterns = Vec::new();

    // Process each language and its artifact types
    for (_lang_key, lang_config) in config.languages {
        // Process each artifact type (cache, build, etc.)
        for (type_key, pattern_config) in lang_config.types {
            // Determine the artifact type based on the TOML key
            // Support variants like "temp_small" by matching prefix
            let artifact_type = if type_key.starts_with("cache") {
                ArtifactType::Cache
            } else if type_key.starts_with("dependencies") {
                ArtifactType::Dependency
            } else if type_key.starts_with("build") {
                ArtifactType::Build
            } else if type_key.starts_with("temp") {
                ArtifactType::Temp
            } else if type_key.starts_with("logs") {
                ArtifactType::Logs
            } else if type_key.starts_with("intermediate") {
                ArtifactType::Intermediate
            } else if type_key.starts_with("ide") {
                ArtifactType::IDE
            } else {
                eprintln!(
                    "Warning: Unknown artifact type '{}', defaulting to Cache",
                    type_key
                );
                ArtifactType::Cache
            };

            // Process each pattern
            for pattern in pattern_config.patterns {
                // Patterns starting with / need context (they only match at project root)
                let needs_context = pattern.starts_with('/');

                // If the pattern starts with /, remove it for the actual matching
                let pattern_normalized = if needs_context {
                    pattern.strip_prefix('/').unwrap_or(&pattern).to_string()
                } else {
                    pattern
                };

                patterns.push(ArtifactPattern {
                    pattern: pattern_normalized,
                    artifact_type,
                    needs_context,
                    language_name: lang_config.name.clone(),
                    aggressive: pattern_config.aggressive,
                });
            }
        }
    }

    Ok(patterns)
}

/// Load artifact patterns from TOML
pub fn load_artifact_patterns() -> Result<Vec<ArtifactPattern>> {
    get_artifact_patterns_from_toml()
}

/// Get artifact patterns, optionally filtering by aggressive mode
pub fn get_artifact_patterns(aggressive: bool) -> Result<Vec<ArtifactPattern>> {
    let all_patterns = load_artifact_patterns()?;

    // Filter out aggressive-only patterns if not in aggressive mode
    let patterns = if aggressive {
        all_patterns
    } else {
        all_patterns.into_iter().filter(|p| !p.aggressive).collect()
    };

    Ok(patterns)
}

/// Check if a path is an artifact based on the patterns
/// Uses a whitelist approach - only returns true for paths that explicitly match known artifact patterns
pub fn is_artifact(path: &Path, patterns: &[ArtifactPattern]) -> bool {
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_default();

    // Now apply whitelist pattern matching - ONLY return true if we match a known artifact pattern
    for pattern in patterns {
        // Handle patterns that need context (starting with /)
        if pattern.needs_context {
            // For root-scoped patterns, we need to check if the filename matches
            // and if the parent directory is a project root
            if filename == pattern.pattern {
                // Check if parent is a project root
                if let Some(parent) = path.parent() {
                    if is_project_root(parent) {
                        return true;
                    }
                }
            }
            continue;
        }

        // Check different pattern types
        if let Some(suffix) = pattern.pattern.strip_prefix('*') {
            // Match against filename for suffix patterns (e.g., *.pyc)
            if filename.ends_with(suffix) {
                return true;
            }
        } else if pattern.pattern.contains('*') {
            // Handle glob patterns - match against filename only
            let parts: Vec<&str> = pattern.pattern.split('*').collect();
            if parts.len() == 2 {
                let filename_str = filename.to_string();
                if filename_str.starts_with(parts[0]) && filename_str.ends_with(parts[1]) {
                    return true;
                }
            }
        } else if filename == pattern.pattern {
            // Exact filename match
            return true;
        } else {
            // Component-based matching: check if pattern matches any path component
            // This prevents false positives like "logs" matching "/catalogs/"
            if path.components().any(|c| {
                if let std::path::Component::Normal(os_str) = c {
                    os_str.to_string_lossy() == pattern.pattern
                } else {
                    false
                }
            }) {
                return true;
            }
        }
    }

    // Default to false - only explicit matches are considered artifacts
    false
}

/// Helper function to check if a path is a project root
fn is_project_root(path: &Path) -> bool {
    let indicators = [
        "Cargo.toml",     // Rust
        "pyproject.toml", // Python
        "package.json",   // JavaScript/Node
        "go.mod",         // Go
        ".git",           // Generic project indicator
        ".jj",            // Jujutsu VCS
    ];

    for indicator in &indicators {
        if path.join(indicator).exists() {
            return true;
        }
    }

    false
}


/// Check if a path is tracked in git by running git ls-files
/// Returns true if the file is tracked in version control
fn is_tracked_in_git(path: &Path) -> bool {
    use std::process::Command;

    // Find the git repository root
    let git_root = Command::new("git")
        .arg("rev-parse")
        .arg("--show-toplevel")
        .current_dir(path.parent().unwrap_or(path))
        .output();

    let git_root = match git_root {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => return false, // Not in a git repo
    };

    // Check if the file is tracked
    let output = Command::new("git")
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg(path)
        .current_dir(&git_root)
        .output();

    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Similar check for jj (Jujutsu)
fn is_tracked_in_jj(path: &Path) -> bool {
    use std::process::Command;

    // Check if file is tracked in jj
    let output = Command::new("jj")
        .arg("file")
        .arg("list")
        .arg(path)
        .output();

    match output {
        Ok(output) => output.status.success() && !output.stdout.is_empty(),
        Err(_) => false,
    }
}

/// Check if a path is tracked in version control (git or jj)
fn is_tracked_in_vcs(path: &Path) -> bool {
    // First check if this is a file (tracked files must be files, not directories)
    if !path.is_file() {
        return false;
    }

    // Check jj first (since projects using jj also have .git)
    if path.ancestors().any(|p| p.join(".jj").exists()) {
        if is_tracked_in_jj(path) {
            return true;
        }
    }

    // Then check git
    if path.ancestors().any(|p| p.join(".git").exists()) {
        if is_tracked_in_git(path) {
            return true;
        }
    }

    false
}

/// Calculate total size of a directory (all files, not just artifacts)
fn calculate_total_dir_size(path: &Path) -> u64 {
    use std::fs;

    let mut total = 0u64;

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();

            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total += metadata.len();
                } else if metadata.is_dir() {
                    // Skip VCS directories
                    if let Some(name) = entry_path.file_name() {
                        if matches!(
                            name.to_str().unwrap_or(""),
                            ".git" | ".jj" | ".svn" | ".hg" | ".bzr" | "_darcs" | ".pijul" | "CVS" | ".fossil"
                        ) {
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

fn scan_for_artifacts(
    paths: &[String],
    delete: bool,
    verbose: bool,
    files: bool,
    dry_run: bool,
    list: bool,
    aggressive: bool,
) -> Result<()> {
    let mut total_bytes: u64 = 0;
    let mut _total_files: u64 = 0;
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let mut skip_paths: HashSet<PathBuf> = HashSet::new(); // Paths to skip (artifact dirs we've already processed)

    // Load patterns once
    let patterns = get_artifact_patterns(aggressive).context("Failed to load artifact patterns")?;

    // Collect a set of artifact patterns that are just filenames (no paths/wildcards)
    // for quick lookup during project language detection
    let _language_files: HashSet<String> = patterns
        .iter() // Iterate over &ArtifactPattern
        .filter(|p| !p.pattern.contains('*') && !p.pattern.contains('/')) // Access pattern field directly
        .map(|p| p.pattern.clone()) // Access pattern field directly
        .collect();

    for start_path_str in paths {
        let start_path = PathBuf::from(start_path_str);
        if verbose {
            println!("DEBUG: Scanning directory {}", start_path.display());
            println!("DEBUG: Directory contents:");
            if let Ok(entries) = fs::read_dir(&start_path) {
                for entry in entries.flatten() {
                    println!("  > {}", entry.path().display());
                }
            }
        }

        let walker = WalkBuilder::new(&start_path)
            .hidden(false) // Include hidden files/dirs by default
            .git_ignore(true)
            .build();

        for result in walker {
            let entry = match result {
                Ok(entry) => entry,
                Err(err) => {
                    eprintln!("Warning: Failed to access entry: {}", err);
                    continue;
                }
            };

            let path = entry.path();

            // Never process the scan root itself as an artifact
            if path == start_path.as_path() {
                continue;
            }

            // Skip VCS directories (version control internals)
            // This matches the common VCS directories that tools like Mutagen and Syncthing skip
            if path.components().any(|c| {
                if let std::path::Component::Normal(name) = c {
                    matches!(
                        name.to_str().unwrap_or(""),
                        ".git" | ".jj" | ".svn" | ".hg" | ".bzr" | "_darcs" | ".pijul" | "CVS" | ".fossil"
                    )
                } else {
                    false
                }
            }) {
                continue;
            }

            // Skip if this path is inside an artifact directory we've already processed
            if skip_paths.iter().any(|skip| path.starts_with(skip)) {
                continue;
            }

            // Try to find project root, but constrain it to be within the scan directory
            let project_root = find_project_root(path)
                .and_then(|root| {
                    // Only use the found root if it's within the scan directory
                    if root.starts_with(&start_path) {
                        Some(root)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| start_path.clone());

            // Add debugging to see each path we check
            if verbose {
                println!("DEBUG: Checking path: {}", path.display());
            }

            // Check if the path is an artifact
            // Pass patterns as a slice
            if is_artifact(path, &patterns) {
                // Use symlink_metadata to avoid following symlinks
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

                // Skip symlinks entirely - don't delete them or their targets
                if metadata.is_symlink() {
                    if verbose {
                        println!("Skipping symlink: {}", path.display());
                    }
                    continue;
                }

                // Handle directories - walk them to find removable files
                if metadata.is_dir() {
                    // Walk the directory and collect untracked files to remove
                    let mut dir_total_size = 0u64;
                    let mut files_to_remove = Vec::new();

                    for entry in walkdir::WalkDir::new(path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .filter(|e| e.file_type().is_file())
                    {
                        let file_path = entry.path();

                        // Check if this file is tracked
                        if !is_tracked_in_vcs(file_path) {
                            if let Ok(meta) = entry.metadata() {
                                let file_size = meta.len();
                                dir_total_size += file_size;
                                files_to_remove.push((file_path.to_path_buf(), file_size));
                            }
                        }
                    }

                    // Only report and remove if there are actually untracked files
                    if !files_to_remove.is_empty() {
                        total_bytes += dir_total_size;

                        let project_report = projects.entry(project_root.clone()).or_insert_with(|| {
                            ProjectReport {
                                artifacts: Vec::new(),
                            }
                        });

                        // Remove files if in delete mode (not dry run)
                        if delete && !dry_run {
                            for (file_path, _) in &files_to_remove {
                                match fs::remove_file(file_path) {
                                    Ok(_) => {
                                        if verbose {
                                            println!("Removed: {}", file_path.display());
                                        }
                                    }
                                    Err(err) => {
                                        if verbose {
                                            eprintln!("Error removing {}: {}", file_path.display(), err);
                                        }
                                    }
                                }
                            }
                        } else if dry_run && list {
                            println!("Would remove: {} ({} untracked files)", path.display(), files_to_remove.len());
                        }

                        // Add directory to report
                        project_report.artifacts.push(ArtifactEntry {
                            path: path.to_path_buf(),
                            size: dir_total_size,
                            removed: delete || dry_run,
                        });
                    }

                    // Add to skip_paths so walker doesn't descend into it again
                    skip_paths.insert(path.to_path_buf());
                    continue;
                }

                // For files: check if tracked in version control
                if is_tracked_in_vcs(path) {
                    if verbose {
                        println!("Skipping tracked file: {}", path.display());
                    }
                    continue;
                }

                // We've already filtered out directories, so this is always a file
                let size = metadata.len();

                total_bytes += size;
                _total_files += 1;

                let project_report = projects.entry(project_root.clone()).or_insert_with(|| {
                    ProjectReport {
                        artifacts: Vec::new(),
                    }
                });

                let removed = if delete || dry_run {
                    if dry_run {
                        if list {
                            println!("Would remove: {}", path.display());
                        }
                        false // Not actually removed in dry run
                    } else {
                        // We only remove files now, directories are handled in cleanup pass
                        match fs::remove_file(path) {
                            Ok(_) => {
                                if verbose {
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
                    false // Not removed if neither delete nor dry_run
                };

                project_report.artifacts.push(ArtifactEntry {
                    path: path.to_path_buf(),
                    size,
                    removed,
                });
            }
        }
    }

    // Cleanup pass: Remove empty directories
    if delete && !dry_run {
        // Collect all directories to check - both artifact dirs and parent dirs of removed files
        let mut dirs_to_check: HashSet<PathBuf> = HashSet::new();

        for project_report in projects.values() {
            for entry in &project_report.artifacts {
                if entry.removed {
                    // If it's a directory artifact, add it
                    if entry.path.is_dir() || entry.path.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false) {
                        dirs_to_check.insert(entry.path.clone());
                        // Also add all parent directories up to the project root
                        let mut current = entry.path.as_path();
                        while let Some(parent) = current.parent() {
                            if dirs_to_check.insert(parent.to_path_buf()) {
                                current = parent;
                            } else {
                                break; // Already added, no need to go further
                            }
                        }
                    } else {
                        // For files, add parent directories
                        if let Some(parent) = entry.path.parent() {
                            dirs_to_check.insert(parent.to_path_buf());
                            // Also add ancestor directories
                            let mut current = parent;
                            while let Some(parent) = current.parent() {
                                if dirs_to_check.insert(parent.to_path_buf()) {
                                    current = parent;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort directories by depth (deepest first) so we remove child dirs before parents
        let mut dirs_vec: Vec<PathBuf> = dirs_to_check.into_iter().collect();
        dirs_vec.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

        // Try to remove empty directories
        for dir in dirs_vec {
            // Skip if doesn't exist
            if !dir.exists() {
                continue;
            }

            // Check if directory is empty
            match fs::read_dir(&dir) {
                Ok(mut entries) => {
                    if entries.next().is_none() {
                        // Directory is empty, try to remove it
                        match fs::remove_dir(&dir) {
                            Ok(_) => {
                                if verbose {
                                    println!("Removed empty directory: {}", dir.display());
                                }
                            }
                            Err(err) => {
                                if verbose {
                                    eprintln!("Warning: Failed to remove directory {}: {}", dir.display(), err);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    // Directory doesn't exist or can't be read, skip
                    continue;
                }
            }
        }
    }


    if projects.is_empty() {
        println!("No artifacts found.");
    } else if !list {
        // Table format (default): alphabetized, relative paths, omit empty projects
        use terminal_size::{Width, terminal_size};

        let start_path = PathBuf::from(&paths[0]);

        // Collect and sort projects by path, filtering out empty projects
        let mut sorted_projects: Vec<_> = projects
            .iter()
            .filter(|(_, report)| {
                let total: u64 = report.artifacts.iter().map(|a| a.size).sum();
                total > 0
            })
            .collect();
        sorted_projects.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

        // Get terminal width (default to 120 if not available)
        let terminal_width = if let Some((Width(w), _)) = terminal_size() {
            w as usize
        } else {
            120
        };

        // Calculate max path width for alignment
        let max_path_width = sorted_projects
            .iter()
            .map(|(path, _)| {
                path.strip_prefix(&start_path)
                    .unwrap_or(path)
                    .display()
                    .to_string()
                    .len()
            })
            .max()
            .unwrap_or(20)
            .min(40); // Cap path width at 40 chars

        // Fixed widths for size columns
        let removable_width = 12;
        let total_width = 12;

        // Calculate What column width
        let separator_width = 6; // spaces between columns
        let what_width = terminal_width
            .saturating_sub(max_path_width)
            .saturating_sub(removable_width)
            .saturating_sub(total_width)
            .saturating_sub(separator_width)
            .max(20);

        // Print header
        println!(
            "{:<path_w$}  {:>rem_w$}  {:>tot_w$}  {}",
            "Path", "Removable", "Total", "What",
            path_w = max_path_width,
            rem_w = removable_width,
            tot_w = total_width
        );
        println!("{}", "─".repeat(terminal_width.min(120)));

        let mut total_removable: u64 = 0;
        let mut total_size: u64 = 0;

        // Print each project
        for (project_dir, report) in sorted_projects {
            let removable_size: u64 = report.artifacts.iter().map(|a| a.size).sum();

            // Skip displaying the root directory line (but include in totals)
            let is_root = project_dir == &start_path;

            // Calculate full size (skip for root to avoid long scan)
            let full_size = if is_root {
                0 // We'll calculate total at the end
            } else {
                calculate_total_dir_size(project_dir)
            };

            total_removable += removable_size;
            total_size += full_size;

            // Skip displaying root directory
            if is_root {
                continue;
            }

            let relative_path = project_dir
                .strip_prefix(&start_path)
                .unwrap_or(project_dir)
                .display()
                .to_string();
            let path_display = if relative_path.is_empty() {
                ".".to_string()
            } else {
                relative_path
            };

            // Collect artifact names sorted by size (largest first)
            let mut artifacts_with_size: Vec<(String, u64)> = report
                .artifacts
                .iter()
                .map(|a| {
                    let name = a.path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    (name, a.size)
                })
                .collect();
            artifacts_with_size.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by size desc

            // Build What column string with truncation
            let mut what_parts = Vec::new();
            let mut current_len = 0;
            let large_threshold = 50 * 1024 * 1024; // 50 MiB

            for (name, size) in &artifacts_with_size {
                let formatted = if *size > large_threshold {
                    format!("{}", name).bold().to_string()
                } else {
                    name.clone()
                };

                let add_len = if what_parts.is_empty() {
                    formatted.len()
                } else {
                    formatted.len() + 2 // ", " separator
                };

                if current_len + add_len + 3 > what_width { // +3 for "..."
                    what_parts.push("...".to_string());
                    break;
                }

                what_parts.push(formatted);
                current_len += add_len;
            }

            let what_display = what_parts.join(", ");

            // Apply styling based on thresholds
            let removable_display = if removable_size > 100 * 1024 * 1024 {
                format_size(removable_size, BINARY).bold().red()
            } else {
                format_size(removable_size, BINARY).normal()
            };

            let path_styled = if full_size > 500 * 1024 * 1024 {
                path_display.bold().yellow()
            } else {
                path_display.normal()
            };

            println!(
                "{:<path_w$}  {:>rem_w$}  {:>tot_w$}  {}",
                path_styled,
                removable_display,
                format_size(full_size, BINARY),
                what_display,
                path_w = max_path_width,
                rem_w = removable_width,
                tot_w = total_width
            );
        }

        println!("{}", "─".repeat(terminal_width.min(120)));
        println!(
            "{:<path_w$}  {:>rem_w$}  {:>tot_w$}",
            "Total",
            format_size(total_removable, BINARY),
            format_size(total_size, BINARY),
            path_w = max_path_width,
            rem_w = removable_width,
            tot_w = total_width
        );
        println!("\nRun with --list to see detailed breakdown by project");
    } else {
        // List format: alphabetized, relative paths, include artifact names
        let start_path = PathBuf::from(&paths[0]);

        // Sort projects alphabetically by path
        let mut sorted_projects: Vec<_> = projects.iter().collect();
        sorted_projects.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

        for (project_dir, report) in sorted_projects {
            let total_project_size: u64 = report.artifacts.iter().map(|a| a.size).sum();

            // Skip empty projects
            if total_project_size == 0 {
                continue;
            }

            // Get relative path from search root
            let relative_path = project_dir
                .strip_prefix(&start_path)
                .unwrap_or(project_dir)
                .display()
                .to_string();
            let path_display = if relative_path.is_empty() {
                ".".to_string()
            } else {
                relative_path
            };

            println!("{}", path_display.bold());

            if files {
                for artifact in &report.artifacts {
                    let rel_artifact = artifact.path
                        .strip_prefix(&start_path)
                        .unwrap_or(&artifact.path);
                    println!(
                        "  - {} ({})",
                        rel_artifact.display(),
                        format_size(artifact.size, BINARY)
                    );
                }
            } else {
                // Aggregate by language and collect artifact names
                let mut language_summary: HashMap<String, (u64, Vec<String>)> = HashMap::new();

                for artifact in &report.artifacts {
                    let path = &artifact.path;
                    let path_str = path.to_string_lossy();
                    let filename = path
                        .file_name()
                        .map(|f| f.to_string_lossy())
                        .unwrap_or_default()
                        .to_string();

                    // Find the matching pattern to get the language
                    if let Some(matching_pattern) = patterns
                        .iter()
                        .find(|p| p.pattern == filename || path_str.contains(&p.pattern))
                    {
                        let entry = language_summary
                            .entry(matching_pattern.language_name.clone())
                            .or_insert((0, Vec::new()));
                        entry.0 += artifact.size;
                        if !entry.1.contains(&filename) {
                            entry.1.push(filename);
                        }
                    }
                }

                // Sort languages alphabetically
                let mut languages: Vec<_> = language_summary.into_iter().collect();
                languages.sort_by(|a, b| a.0.cmp(&b.0));

                for (language, (size, artifacts)) in languages {
                    let artifacts_str = artifacts.join(", ");
                    println!("  - {}: {} ({})", language, format_size(size, BINARY), artifacts_str);
                }
            }

            println!(
                "  {}",
                format!(
                    "Total: {}",
                    format_size(total_project_size, BINARY)
                )
                .green()
            );
            println!(); // Add a blank line between projects
        }

        println!("========================================");
        println!(
            "Total Size Found: {}",
            format_size(total_bytes, BINARY).bold()
        );
        if delete && !dry_run {
            let removed_bytes: u64 = projects
                .values()
                .flat_map(|r| &r.artifacts)
                .filter(|a| a.removed)
                .map(|a| a.size)
                .sum();
            println!(
                "Total Size Removed: {}",
                format_size(removed_bytes, BINARY).bold().red()
            );
        } else if dry_run {
            println!("Dry run mode: No files were deleted.");
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    scan_for_artifacts(
        &args.paths,
        args.delete,
        args.verbose,
        args.files,
        args.dry_run,
        args.list,
        args.aggressive,
    )?;

    Ok(())
}
