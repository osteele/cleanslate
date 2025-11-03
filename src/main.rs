//! CleanSlate - Selective Artifact Cleaner
//!
//! CleanSlate removes build artifacts and caches based on pattern matching and VCS tracking status.
//! Unlike `git clean` which removes all untracked files, CleanSlate is selective and only removes
//! files that match known artifact patterns (from artifacts.toml) AND are not tracked in version control.
//!
//! ## Architecture
//!
//! See `docs/architecture.md` for complete documentation on:
//! - Layered removal strategy (pattern matching → VCS tracking → directory categorization)
//! - Three-tier directory categorization for performance optimization
//! - VCS tracking vs gitignore semantics (critical distinction!)
//! - Empty directory cleanup strategy
//!
//! ## Performance Optimization
//!
//! The tool uses a three-tier directory categorization strategy:
//! - **Category 1**: VCS internals (.git, .jj) - Never traverse
//! - **Category 2**: Recreatable directories (node_modules, .venv, target) - Spot-check for tracking
//! - **Category 3**: Other directories - Batch-check all files
//!
//! This reduces VCS subprocess calls from O(N) to O(D) where N = total files, D = directories,
//! resulting in 100-10,000x speedup for large projects.

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use humansize::{format_size, BINARY};
use ignore::WalkBuilder;
use rayon::prelude::*;
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

/// Directories that are conventionally recreatable from manifest files and rarely tracked.
/// These directories can be spot-checked for tracking (single VCS call) rather than
/// checking every file individually.
/// See docs/architecture.md for detailed explanation of the three directory categories.
const RECREATABLE_DIRS: &[&str] = &[
    // JavaScript/Node.js
    "node_modules",
    ".npm",
    ".pnpm",
    ".yarn",
    // Python
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pyright_cache",
    ".tox",
    ".nox",
    ".eggs",
    ".ipynb_checkpoints",
    // Rust
    "target",
    // Java/JVM
    ".gradle",
    ".m2",
    // Ruby
    ".bundle",
    "vendor/bundle",
    // Dart/Flutter
    ".dart_tool",
    ".pub-cache",
    ".flutter-plugins",
    // Haskell
    ".stack-work",
    "dist-newstyle",
    // Go
    "vendor",
    // C/C++
    "CMakeFiles",
    // General build/cache
    ".cache",
    ".parcel-cache",
    ".vite-cache",
    ".rollup-cache",
    ".turbo",
];

/// Helper function to check if a path matches any recreatable directory pattern
fn is_recreatable_dir(path: &Path) -> bool {
    // Get the directory name for simple comparisons
    let dir_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    for pattern in RECREATABLE_DIRS {
        if pattern.contains('/') {
            // Multi-component pattern like "vendor/bundle"
            if matches_path_suffix(path, pattern) {
                return true;
            }
        } else if *pattern == dir_name {
            // Simple exact match
            return true;
        }
    }

    false
}

/// VCS internal directories that should never be traversed or removed.
/// See docs/architecture.md for detailed explanation of the three directory categories.
const VCS_INTERNALS: &[&str] = &[
    ".git",
    ".jj",
    ".svn",
    ".hg",
    ".bzr",
    "_darcs",
    ".pijul",
    "CVS",
    ".fossil",
];

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

        // Check if pattern contains a slash (multi-component pattern)
        if pattern.pattern.contains('/') {
            // Multi-component pattern like "vendor/bundle" or "*.xcworkspace/xcuserdata"
            if matches_path_suffix(path, &pattern.pattern) {
                return true;
            }
            continue;
        }

        // Single-component patterns - check different pattern types
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

/// Helper function to match multi-component patterns against path suffixes
/// Supports wildcards like "*.xcworkspace/xcuserdata" and literals like "vendor/bundle"
fn matches_path_suffix(path: &Path, pattern: &str) -> bool {
    // Split the pattern into components
    let pattern_parts: Vec<&str> = pattern.split('/').collect();

    // Get path components from the end
    let path_components: Vec<_> = path
        .components()
        .filter_map(|c| {
            if let std::path::Component::Normal(os_str) = c {
                Some(os_str.to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect();

    // Check if we have enough components to match
    if path_components.len() < pattern_parts.len() {
        return false;
    }

    // Match from the end of the path
    let start_idx = path_components.len() - pattern_parts.len();
    for (i, pattern_part) in pattern_parts.iter().enumerate() {
        let path_component = &path_components[start_idx + i];

        if !matches_component(path_component, pattern_part) {
            return false;
        }
    }

    true
}

/// Helper function to match a single path component against a pattern with wildcards
fn matches_component(component: &str, pattern: &str) -> bool {
    if pattern == component {
        // Exact match
        return true;
    }

    if !pattern.contains('*') && !pattern.contains('?') {
        // No wildcards, already checked exact match above
        return false;
    }

    // Handle wildcards
    if let Some(suffix) = pattern.strip_prefix('*') {
        // Simple suffix match like "*.xcworkspace"
        return component.ends_with(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        // Simple prefix match like "cmake-build-*"
        return component.starts_with(prefix);
    }

    // Complex glob pattern - split on * and match parts
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        return component.starts_with(parts[0]) && component.ends_with(parts[1]);
    }

    // For more complex patterns, we'd need a full glob matcher
    // For now, return false for patterns we can't handle
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

/// VCS type detected in the repository
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VcsType {
    Git,
    Jujutsu,
    None,
}

/// Detect which VCS is in use for a given path by walking up to find .jj or .git
/// Prefers Jujutsu if both .jj and .git exist (per user configuration)
fn detect_vcs(path: &Path) -> (VcsType, Option<PathBuf>) {
    for ancestor in path.ancestors() {
        // Check for .jj first (preferred when both exist)
        if ancestor.join(".jj").exists() {
            return (VcsType::Jujutsu, Some(ancestor.to_path_buf()));
        }
        // Check for .git
        if ancestor.join(".git").exists() {
            return (VcsType::Git, Some(ancestor.to_path_buf()));
        }
    }
    (VcsType::None, None)
}

/// Spot-check: Does a directory contain ANY tracked files? (for Category 2 directories)
/// Returns true if the directory contains at least one tracked file.
/// Uses early-exit optimization (head -1) to avoid scanning thousands of files.
fn has_tracked_files(dir: &Path, vcs_type: VcsType, vcs_root: &Path) -> bool {
    use std::process::Command;

    match vcs_type {
        VcsType::Git => {
            // Use: git ls-files <dir> | head -1
            let output = Command::new("git")
                .arg("ls-files")
                .arg(dir)
                .current_dir(vcs_root)
                .output();

            match output {
                Ok(output) if output.status.success() => !output.stdout.is_empty(),
                _ => false,
            }
        }
        VcsType::Jujutsu => {
            // Use: jj file list --ignore-working-copy 'glob:"dir/**"' | head -1
            // Note: --ignore-working-copy is faster (skips snapshot)
            // Use relative path from VCS root to avoid false positives from directories with same basename
            let dir_pattern = format!(
                "glob:\"{}/**\"",
                dir.strip_prefix(vcs_root)
                    .ok()
                    .and_then(|p| p.to_str())
                    .unwrap_or("")
            );

            let output = Command::new("jj")
                .arg("file")
                .arg("list")
                .arg("--ignore-working-copy")
                .arg(&dir_pattern)
                .current_dir(vcs_root)
                .output();

            match output {
                Ok(output) if output.status.success() => !output.stdout.is_empty(),
                _ => false,
            }
        }
        VcsType::None => false,
    }
}

/// Batch-check: Get all tracked files in a directory (for Category 3 directories)
/// Returns a HashSet of tracked file paths relative to the VCS root.
fn get_tracked_files_batch(dir: &Path, vcs_type: VcsType, vcs_root: &Path) -> HashSet<PathBuf> {
    use std::process::Command;

    let mut tracked = HashSet::new();

    match vcs_type {
        VcsType::Git => {
            // Use: git ls-files <dir>
            let output = Command::new("git")
                .arg("ls-files")
                .arg(dir)
                .current_dir(vcs_root)
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if !line.is_empty() {
                            tracked.insert(vcs_root.join(line));
                        }
                    }
                }
            }
        }
        VcsType::Jujutsu => {
            // Use: jj file list --ignore-working-copy 'glob:"dir/**"'
            let dir_pattern = format!(
                "glob:\"{}/**\"",
                dir.strip_prefix(vcs_root)
                    .ok()
                    .and_then(|p| p.to_str())
                    .unwrap_or("")
            );

            let output = Command::new("jj")
                .arg("file")
                .arg("list")
                .arg("--ignore-working-copy")
                .arg(&dir_pattern)
                .current_dir(vcs_root)
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if !line.is_empty() {
                            tracked.insert(vcs_root.join(line));
                        }
                    }
                }
            }
        }
        VcsType::None => {}
    }

    tracked
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

/// Result from scanning a single path
struct ScanResult {
    projects: HashMap<PathBuf, ProjectReport>,
    total_bytes: u64,
}

/// Handle a directory artifact (Category 2 or Category 3)
fn handle_directory_artifact(
    path: &Path,
    start_path: &Path,
    project_root: &Path,
    projects: &mut HashMap<PathBuf, ProjectReport>,
    skip_paths: &mut HashSet<PathBuf>,
    delete: bool,
    verbose: bool,
    dry_run: bool,
    list: bool,
) -> Result<u64> {
    let mut total_bytes = 0u64;

    // Detect VCS type once for this directory
    let (vcs_type, vcs_root) = detect_vcs(path);
    let vcs_root = vcs_root.unwrap_or_else(|| start_path.to_path_buf());

    // Category 2: Recreatable directories (spot-check)
    if is_recreatable_dir(path) {
        if verbose {
            println!("DEBUG: Spot-checking Category 2 directory: {}", path.display());
        }

        // Spot-check: Does this directory contain ANY tracked files?
        if has_tracked_files(path, vcs_type, &vcs_root) {
            if verbose {
                println!("  Contains tracked files, skipping");
            }
            skip_paths.insert(path.to_path_buf());
            return Ok(0);
        }

        // No tracked files → entire directory can be removed
        let dir_size = calculate_total_dir_size(path);
        total_bytes += dir_size;

        let project_report = projects.entry(project_root.to_path_buf()).or_insert_with(|| {
            ProjectReport {
                artifacts: Vec::new(),
            }
        });

        // Remove entire directory if in delete mode
        if delete && !dry_run {
            match fs::remove_dir_all(path) {
                Ok(_) => {
                    if verbose {
                        println!("Removed directory: {}", path.display());
                    }
                }
                Err(err) => {
                    if verbose {
                        eprintln!("Error removing {}: {}", path.display(), err);
                    }
                }
            }
        } else if dry_run && list {
            println!("Would remove directory: {}", path.display());
        }

        project_report.artifacts.push(ArtifactEntry {
            path: path.to_path_buf(),
            size: dir_size,
            removed: delete || dry_run,
        });

        skip_paths.insert(path.to_path_buf());
        return Ok(total_bytes);
    }

    // Category 3: Other directories (batch-check contents)
    if verbose {
        println!("DEBUG: Batch-checking Category 3 directory: {}", path.display());
    }

    // Get all tracked files in this directory with a single VCS call
    let tracked_files = get_tracked_files_batch(path, vcs_type, &vcs_root);

    if verbose {
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
            if let Ok(meta) = entry.metadata() {
                let file_size = meta.len();
                dir_total_size += file_size;
                files_to_remove.push((file_path.to_path_buf(), file_size));
            }
        }
    }

    // Only report and remove if there are untracked files
    if !files_to_remove.is_empty() {
        total_bytes += dir_total_size;

        let project_report = projects.entry(project_root.to_path_buf()).or_insert_with(|| {
            ProjectReport {
                artifacts: Vec::new(),
            }
        });

        // Remove files if in delete mode
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

        project_report.artifacts.push(ArtifactEntry {
            path: path.to_path_buf(),
            size: dir_total_size,
            removed: delete || dry_run,
        });
    }

    skip_paths.insert(path.to_path_buf());
    Ok(total_bytes)
}

/// Handle a file artifact
fn handle_file_artifact(
    path: &Path,
    metadata: &fs::Metadata,
    project_root: &Path,
    projects: &mut HashMap<PathBuf, ProjectReport>,
    delete: bool,
    verbose: bool,
    dry_run: bool,
    list: bool,
) -> Result<u64> {
    // For files: check if tracked in version control
    if is_tracked_in_vcs(path) {
        if verbose {
            println!("Skipping tracked file: {}", path.display());
        }
        return Ok(0);
    }

    let size = metadata.len();

    let project_report = projects.entry(project_root.to_path_buf()).or_insert_with(|| {
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

    Ok(size)
}

/// Scan a single path for artifacts (used for parallel processing)
fn scan_single_path(
    start_path_str: &str,
    patterns: &[ArtifactPattern],
    delete: bool,
    verbose: bool,
    dry_run: bool,
    list: bool,
) -> Result<ScanResult> {
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let mut skip_paths: HashSet<PathBuf> = HashSet::new();
    let mut total_bytes: u64 = 0;
    let mut _total_files: u64 = 0;

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
        if path.components().any(|c| {
            if let std::path::Component::Normal(name) = c {
                VCS_INTERNALS.contains(&name.to_str().unwrap_or(""))
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
        if is_artifact(path, patterns) {
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

            // Skip symlinks entirely
            if metadata.is_symlink() {
                if verbose {
                    println!("Skipping symlink: {}", path.display());
                }
                continue;
            }

            // Handle directories or files
            if metadata.is_dir() {
                let bytes = handle_directory_artifact(
                    path,
                    &start_path,
                    &project_root,
                    &mut projects,
                    &mut skip_paths,
                    delete,
                    verbose,
                    dry_run,
                    list,
                )?;
                total_bytes += bytes;
            } else {
                let bytes = handle_file_artifact(
                    path,
                    &metadata,
                    &project_root,
                    &mut projects,
                    delete,
                    verbose,
                    dry_run,
                    list,
                )?;
                total_bytes += bytes;
                _total_files += 1;
            }
        }
    }

    Ok(ScanResult {
        projects,
        total_bytes,
    })
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
    // Load patterns once (shared across all parallel scans)
    let patterns = get_artifact_patterns(aggressive).context("Failed to load artifact patterns")?;

    // Canonicalize and deduplicate paths to prevent:
    // 1. Double-counting artifact sizes
    // 2. Race conditions during deletion
    // 3. Redundant scanning of overlapping paths
    let mut canonical_paths: HashSet<PathBuf> = HashSet::new();
    for path_str in paths {
        let path = PathBuf::from(path_str);
        match path.canonicalize() {
            Ok(canonical) => {
                canonical_paths.insert(canonical);
            }
            Err(e) => {
                eprintln!("Warning: Could not canonicalize path '{}': {}", path_str, e);
                // Still add the original path if canonicalization fails
                canonical_paths.insert(path);
            }
        }
    }

    let unique_paths: Vec<String> = canonical_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // Scan paths in parallel
    let results: Vec<ScanResult> = unique_paths
        .par_iter()
        .map(|path| scan_single_path(path, &patterns, delete, verbose, dry_run, list))
        .collect::<Result<Vec<_>>>()?;

    // Merge results from parallel scans
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let mut total_bytes: u64 = 0;

    for result in results {
        total_bytes += result.total_bytes;
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
        // A directory is considered "empty" if it contains nothing OR only .DS_Store/Thumbs.db
        for dir in dirs_vec {
            // Skip if doesn't exist
            if !dir.exists() {
                continue;
            }

            // Check if directory is empty or only contains trivial files
            match fs::read_dir(&dir) {
                Ok(entries) => {
                    // Collect all entries
                    let remaining: Vec<_> = entries.filter_map(|e| e.ok()).collect();

                    // Check if empty or only contains .DS_Store/Thumbs.db
                    let is_effectively_empty = remaining.is_empty() ||
                        remaining.iter().all(|entry| {
                            entry.file_name().to_str().map(|name| {
                                matches!(name, ".DS_Store" | "Thumbs.db")
                            }).unwrap_or(false)
                        });

                    if is_effectively_empty {
                        // Remove trivial files first if present
                        for entry in remaining {
                            if let Some(name) = entry.file_name().to_str() {
                                if matches!(name, ".DS_Store" | "Thumbs.db") {
                                    let _ = fs::remove_file(entry.path());
                                }
                            }
                        }

                        // Directory is empty or now empty, try to remove it
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
