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

/// Result of a VCS tracking check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VcsCheckResult {
    /// File is tracked in version control
    Tracked,
    /// File is not tracked in version control
    Untracked,
    /// VCS check failed - status unknown
    Unknown(String),
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
/// Returns VcsCheckResult indicating tracked, untracked, or error
fn is_tracked_in_git(path: &Path) -> VcsCheckResult {
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
        Ok(_) => {
            // Git command ran but failed (e.g., not a git repo)
            return VcsCheckResult::Untracked;
        }
        Err(e) => {
            return VcsCheckResult::Unknown(format!("git rev-parse failed: {}", e));
        }
    };

    // Check if the file is tracked
    let output = Command::new("git")
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg(path)
        .current_dir(&git_root)
        .output();

    match output {
        Ok(output) if output.status.success() => VcsCheckResult::Tracked,
        Ok(_) => VcsCheckResult::Untracked, // Command ran but file not tracked
        Err(e) => VcsCheckResult::Unknown(format!("git ls-files failed: {}", e)),
    }
}

/// Similar check for jj (Jujutsu)
/// Returns VcsCheckResult indicating tracked, untracked, or error
fn is_tracked_in_jj(path: &Path) -> VcsCheckResult {
    // Check if file is tracked in jj
    let output = Command::new("jj")
        .arg("file")
        .arg("list")
        .arg(path)
        .output();

    match output {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            VcsCheckResult::Tracked
        }
        Ok(_) => VcsCheckResult::Untracked,
        Err(e) => VcsCheckResult::Unknown(format!("jj file list failed: {}", e)),
    }
}

/// Check if a path is tracked in version control (git or jj)
/// Returns VcsCheckResult indicating tracked, untracked, or error
pub fn is_tracked_in_vcs(path: &Path) -> VcsCheckResult {
    // First check if this is a file (tracked files must be files, not directories)
    if !path.is_file() {
        return VcsCheckResult::Untracked;
    }

    // Check jj first (since projects using jj also have .git)
    if path.ancestors().any(|p| p.join(".jj").exists()) {
        return is_tracked_in_jj(path);
    }

    // Then check git
    if path.ancestors().any(|p| p.join(".git").exists()) {
        return is_tracked_in_git(path);
    }

    // No VCS found
    VcsCheckResult::Untracked
}

/// Spot-check: Does a directory contain ANY tracked files? (for Category 2 directories)
/// Returns Some(true) if tracked files exist, Some(false) if none, None on VCS error.
/// Uses early-exit optimization (head -1) to avoid scanning thousands of files.
pub fn has_tracked_files(dir: &Path, vcs_type: VcsType, vcs_root: &Path) -> Option<bool> {
    match vcs_type {
        VcsType::Git => {
            // Use: git ls-files <dir> | head -1
            let output = Command::new("git")
                .arg("ls-files")
                .arg(dir)
                .current_dir(vcs_root)
                .output();

            match output {
                Ok(output) if output.status.success() => Some(!output.stdout.is_empty()),
                Ok(_) => Some(false), // Command ran but failed (likely empty dir)
                Err(_) => None,       // Command execution error
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
                Ok(output) if output.status.success() => Some(!output.stdout.is_empty()),
                Ok(_) => Some(false), // Command ran but no tracked files
                Err(_) => None,       // Command execution error
            }
        }
        VcsType::None => Some(false),
    }
}

/// Batch-check: Get all tracked files in a directory (for Category 3 directories)
/// Returns Ok(HashSet) of tracked file paths, or Err(String) if VCS command failed.
pub fn get_tracked_files_batch(
    dir: &Path,
    vcs_type: VcsType,
    vcs_root: &Path,
) -> Result<HashSet<PathBuf>, String> {
    let mut tracked = HashSet::new();

    match vcs_type {
        VcsType::Git => {
            // Use: git ls-files <dir>
            let output = Command::new("git")
                .arg("ls-files")
                .arg(dir)
                .current_dir(vcs_root)
                .output()
                .map_err(|e| format!("git ls-files failed: {}", e))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if !line.is_empty() {
                        tracked.insert(vcs_root.join(line));
                    }
                }
            }
            // Note: Non-success status (e.g., empty dir) is not an error, just no tracked files
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
                .output()
                .map_err(|e| format!("jj file list failed: {}", e))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if !line.is_empty() {
                        tracked.insert(vcs_root.join(line));
                    }
                }
            }
        }
        VcsType::None => {}
    }

    Ok(tracked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // ============ detect_vcs tests ============

    #[test]
    fn test_detect_vcs_git_only() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join(".git")).unwrap();

        let (vcs_type, root) = detect_vcs(temp.path());
        assert_eq!(vcs_type, VcsType::Git);
        assert_eq!(root, Some(temp.path().to_path_buf()));
    }

    #[test]
    fn test_detect_vcs_jj_only() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join(".jj")).unwrap();

        let (vcs_type, root) = detect_vcs(temp.path());
        assert_eq!(vcs_type, VcsType::Jujutsu);
        assert_eq!(root, Some(temp.path().to_path_buf()));
    }

    #[test]
    fn test_detect_vcs_both_prefers_jj() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join(".git")).unwrap();
        fs::create_dir(temp.path().join(".jj")).unwrap();

        let (vcs_type, root) = detect_vcs(temp.path());
        assert_eq!(vcs_type, VcsType::Jujutsu);
        assert_eq!(root, Some(temp.path().to_path_buf()));
    }

    #[test]
    fn test_detect_vcs_none() {
        let temp = tempdir().unwrap();
        // No VCS directories

        let (vcs_type, root) = detect_vcs(temp.path());
        assert_eq!(vcs_type, VcsType::None);
        assert_eq!(root, None);
    }

    #[test]
    fn test_detect_vcs_nested_finds_parent() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join(".git")).unwrap();
        let nested = temp.path().join("src").join("lib");
        fs::create_dir_all(&nested).unwrap();

        let (vcs_type, root) = detect_vcs(&nested);
        assert_eq!(vcs_type, VcsType::Git);
        assert_eq!(root, Some(temp.path().to_path_buf()));
    }

    #[test]
    fn test_detect_vcs_nested_with_file() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join(".git")).unwrap();
        let nested = temp.path().join("src");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("main.rs");
        fs::write(&file, "fn main() {}").unwrap();

        let (vcs_type, root) = detect_vcs(&file);
        assert_eq!(vcs_type, VcsType::Git);
        assert_eq!(root, Some(temp.path().to_path_buf()));
    }

    // ============ VCS_INTERNALS tests ============

    #[test]
    fn test_vcs_internals_contains_common_vcs() {
        assert!(VCS_INTERNALS.contains(&".git"));
        assert!(VCS_INTERNALS.contains(&".jj"));
        assert!(VCS_INTERNALS.contains(&".svn"));
        assert!(VCS_INTERNALS.contains(&".hg"));
    }

    #[test]
    fn test_vcs_internals_does_not_contain_artifacts() {
        assert!(!VCS_INTERNALS.contains(&"node_modules"));
        assert!(!VCS_INTERNALS.contains(&"target"));
        assert!(!VCS_INTERNALS.contains(&".venv"));
    }
}
