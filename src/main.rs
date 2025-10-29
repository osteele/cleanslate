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

    /// Show rm commands that would be run, but don't execute them
    #[arg(long)]
    dry_run: bool,
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
    artifact_type: ArtifactType,
    /// Is this a standalone pattern or should it be properly contextualized?
    /// For example, "dist" should only match at the project root level, not any directory named "dist"
    needs_context: bool,
    /// The name of the language this pattern belongs to (e.g., "Python", "JavaScript")
    language_name: String,
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
            let artifact_type = match type_key.as_str() {
                "cache" => ArtifactType::Cache,
                "dependencies" => ArtifactType::Dependency,
                "build" => ArtifactType::Build,
                "temp" => ArtifactType::Temp,
                "logs" => ArtifactType::Logs,
                "intermediate" => ArtifactType::Intermediate,
                "ide" => ArtifactType::IDE,
                _ => {
                    eprintln!(
                        "Warning: Unknown artifact type '{}', defaulting to Cache",
                        type_key
                    );
                    ArtifactType::Cache
                }
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

/// Alias for backward compatibility
pub fn get_artifact_patterns() -> Result<Vec<ArtifactPattern>> {
    load_artifact_patterns()
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

fn calculate_dir_size(path: &Path) -> Result<u64> {
    let mut total = 0;

    // First check if path exists
    if !path.exists() {
        return Ok(0);
    }

    // Use symlink_metadata to avoid following symlinks
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            eprintln!(
                "Warning: Could not get metadata for {}: {}",
                path.display(),
                err
            );
            return Ok(0);
        }
    };

    // Skip symlinks entirely - don't follow them or count their size
    if metadata.is_symlink() {
        return Ok(0);
    }

    if metadata.is_file() {
        return Ok(metadata.len());
    }

    let read_dir_result = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!(
                "Warning: Failed to read directory {}: {}",
                path.display(),
                err
            );
            return Ok(0);
        }
    };

    for entry_result in read_dir_result {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                eprintln!(
                    "Warning: Error reading entry in {}: {}",
                    path.display(),
                    err
                );
                continue;
            }
        };

        let entry_path = entry.path();

        // Use symlink_metadata to check if this entry is a symlink
        let entry_metadata = match fs::symlink_metadata(&entry_path) {
            Ok(meta) => meta,
            Err(err) => {
                eprintln!(
                    "Warning: Could not get metadata for {}: {}",
                    entry_path.display(),
                    err
                );
                continue;
            }
        };

        // Skip symlinks - don't recurse into them or count their size
        if entry_metadata.is_symlink() {
            continue;
        }

        if entry_metadata.is_dir() {
            total += calculate_dir_size(&entry_path).unwrap_or(0);
        } else {
            total += entry_metadata.len();
        }
    }

    Ok(total)
}

pub fn find_project_root(path: &Path) -> Option<PathBuf> {
    let indicators = [
        "Cargo.toml",     // Rust
        "pyproject.toml", // Python
        "package.json",   // JavaScript/Node
        "go.mod",         // Go
        ".git",           // Generic project indicator
    ];

    let mut current = Some(path);

    while let Some(path) = current {
        for indicator in &indicators {
            if path.join(indicator).exists() {
                return Some(path.to_path_buf());
            }
        }

        current = path.parent();
    }

    // If we couldn't determine a project root, return the original path
    Some(path.to_path_buf())
}

fn scan_for_artifacts(
    paths: &[String],
    delete: bool,
    verbose: bool,
    files: bool,
    dry_run: bool,
) -> Result<()> {
    let mut total_bytes: u64 = 0;
    let mut _total_files: u64 = 0;
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let mut language_counts: HashMap<ArtifactType, HashMap<PathBuf, String>> = HashMap::new();

    // Load patterns once
    let patterns = get_artifact_patterns().context("Failed to load artifact patterns")?;

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

            // Try to find project root, default to start_path if not found
            let project_root = find_project_root(path).unwrap_or_else(|| start_path.clone());

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

                let size = if metadata.is_file() {
                    metadata.len()
                } else {
                    // For directories, calculate size recursively but handle errors
                    calculate_dir_size(path).unwrap_or_else(|err| {
                        eprintln!(
                            "Warning: Could not calculate size for directory {}: {}",
                            path.display(),
                            err
                        );
                        0
                    })
                };

                total_bytes += size;
                _total_files += 1;

                let project_report = projects.entry(project_root.clone()).or_insert_with(|| {
                    ProjectReport {
                        artifacts: Vec::new(),
                    }
                });

                let removed = if delete {
                    if dry_run {
                        println!("Would remove: {}", path.display());
                        false // Not actually removed in dry run
                    } else {
                        let removal_result = if metadata.is_dir() {
                            fs::remove_dir_all(path)
                        } else {
                            fs::remove_file(path)
                        };
                        match removal_result {
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
                    false // Not removed if delete flag is false
                };

                project_report.artifacts.push(ArtifactEntry {
                    path: path.to_path_buf(),
                    size,
                    removed,
                });
            }
        }
    }

    // Function to detect languages based on common files
    fn detect_project_languages(project_path: &Path, patterns: &[ArtifactPattern]) -> Vec<String> {
        let mut detected_languages = HashSet::new();
        let read_dir_result = match fs::read_dir(project_path) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!(
                    "Warning: Failed to read directory {}: {}",
                    project_path.display(),
                    err
                );
                return Vec::new(); // Return empty if we can't read the directory
            }
        };

        for entry in read_dir_result.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    let path_str = path.to_string_lossy();
                    // Find the pattern that matches this file
                    // Iterate over &ArtifactPattern
                    if let Some(matching_pattern) = patterns
                        .iter()
                        .find(|p| p.pattern == filename || path_str.contains(&p.pattern))
                    {
                        // Check if the artifact type suggests a language
                        let artifact_type: Option<ArtifactType> = patterns
                            .iter()
                            .find(|p| p.pattern == filename || path_str.contains(&p.pattern))
                            .map(|p| p.artifact_type); // Access artifact_type field directly
                        if let Some(atype) = artifact_type {
                            if !matches!(
                                atype,
                                ArtifactType::Temp | ArtifactType::Logs | ArtifactType::IDE
                            ) {
                                detected_languages.insert(matching_pattern.language_name.clone());
                            }
                        }
                    }
                }
            }
        }
        // Convert HashSet to Vec for the return type
        detected_languages.into_iter().collect()
    }

    if projects.is_empty() {
        println!("No artifacts found.");
    } else {
        for (project_dir, report) in &projects {
            let project_name = project_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let project_path_display = project_dir.display();
            let total_project_size: u64 = report.artifacts.iter().map(|a| a.size).sum();

            // Detect languages for this project
            let languages = detect_project_languages(project_dir, &patterns); // Pass patterns slice
            let language_str = if languages.is_empty() {
                String::new()
            } else {
                format!(" ({})", languages.join(", "))
            };

            println!(
                "{}",
                format!(
                    "Project: {} ({}){}",
                    project_name, project_path_display, language_str
                )
                .bold()
            );

            if files {
                for artifact in &report.artifacts {
                    println!(
                        "  - {} ({})",
                        artifact.path.display(),
                        format_size(artifact.size, BINARY)
                    );
                }
            } else {
                // Aggregate counts per language within the project
                let mut project_language_summary: HashMap<String, u64> = HashMap::new();
                for artifact in &report.artifacts {
                    let path = &artifact.path;
                    let path_str = path.to_string_lossy();
                    let filename = path
                        .file_name()
                        .map(|f| f.to_string_lossy())
                        .unwrap_or_default();

                    // Find the matching pattern to get the language
                    // Iterate over &ArtifactPattern
                    if let Some(matching_pattern) = patterns
                        .iter()
                        .find(|p| p.pattern == filename || path_str.contains(&p.pattern))
                    {
                        *project_language_summary
                            .entry(matching_pattern.language_name.clone())
                            .or_insert(0) += artifact.size;
                        // Also update global language counts
                        let language_map = language_counts
                            .entry(matching_pattern.artifact_type) // Access artifact_type field directly
                            .or_default();
                        language_map
                            .entry(path.to_path_buf())
                            .or_insert(matching_pattern.language_name.clone()); // Access language_name field directly
                    }
                }

                for (language, size) in project_language_summary {
                    println!("  - {}: {}", language, format_size(size, BINARY));
                }
            }

            println!(
                "  {}",
                format!(
                    "Total Project Size: {}",
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
    )?;

    Ok(())
}
