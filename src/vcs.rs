//! VCS detection and tracking checks for Git and Jujutsu.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// VCS internal directories that should never be traversed or removed.
/// See docs/architecture.md for detailed explanation of the three directory categories.
pub const VCS_INTERNALS: &[&str] = &[
    ".git", ".jj", ".svn", ".hg", ".bzr", "_darcs", ".pijul", "CVS", ".fossil",
];

/// VCS type detected in the repository
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcsType {
    Git,
    Jujutsu,
    None,
}

/// Detect which VCS is in use for a given path by walking up to find .jj or .git
/// Prefers Jujutsu if both .jj and .git exist (per user configuration)
pub fn detect_vcs(path: &Path) -> (VcsType, Option<PathBuf>) {
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

/// Check if a path is tracked in git by running git ls-files
/// Returns true if the file is tracked in version control
fn is_tracked_in_git(path: &Path) -> bool {
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
pub fn is_tracked_in_vcs(path: &Path) -> bool {
    // First check if this is a file (tracked files must be files, not directories)
    if !path.is_file() {
        return false;
    }

    // Check jj first (since projects using jj also have .git)
    if path.ancestors().any(|p| p.join(".jj").exists()) && is_tracked_in_jj(path) {
        return true;
    }

    // Then check git
    if path.ancestors().any(|p| p.join(".git").exists()) && is_tracked_in_git(path) {
        return true;
    }

    false
}

/// Spot-check: Does a directory contain ANY tracked files? (for Category 2 directories)
/// Returns true if the directory contains at least one tracked file.
/// Uses early-exit optimization (head -1) to avoid scanning thousands of files.
pub fn has_tracked_files(dir: &Path, vcs_type: VcsType, vcs_root: &Path) -> bool {
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
pub fn get_tracked_files_batch(dir: &Path, vcs_type: VcsType, vcs_root: &Path) -> HashSet<PathBuf> {
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
