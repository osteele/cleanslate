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
fn is_tracked_in_git(path: &Path, git_root: &Path) -> VcsCheckResult {
    let relative_path = match path.strip_prefix(git_root) {
        Ok(path) => path,
        Err(error) => {
            return VcsCheckResult::Unknown(format!(
                "{} is outside Git root {}: {}",
                path.display(),
                git_root.display(),
                error
            ));
        }
    };

    let output = Command::new("git")
        .arg("ls-files")
        .arg("--")
        .arg(relative_path)
        .current_dir(git_root)
        .output();

    match output {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            VcsCheckResult::Tracked
        }
        Ok(output) if output.status.success() => VcsCheckResult::Untracked,
        Ok(output) => VcsCheckResult::Unknown(command_failure("git ls-files", &output)),
        Err(e) => VcsCheckResult::Unknown(format!("git ls-files failed: {}", e)),
    }
}

/// Similar check for jj (Jujutsu)
/// Returns VcsCheckResult indicating tracked, untracked, or error
fn is_tracked_in_jj(path: &Path, jj_root: &Path) -> VcsCheckResult {
    let relative_path = match path.strip_prefix(jj_root) {
        Ok(path) => path,
        Err(error) => {
            return VcsCheckResult::Unknown(format!(
                "{} is outside Jujutsu root {}: {}",
                path.display(),
                jj_root.display(),
                error
            ));
        }
    };

    let output = Command::new("jj")
        .arg("file")
        .arg("list")
        .arg(relative_path)
        .current_dir(jj_root)
        .output();

    match output {
        Ok(output) if output.status.success() && !output.stdout.is_empty() => {
            VcsCheckResult::Tracked
        }
        Ok(output) if output.status.success() => VcsCheckResult::Untracked,
        Ok(output) => VcsCheckResult::Unknown(command_failure("jj file list", &output)),
        Err(e) => VcsCheckResult::Unknown(format!("jj file list failed: {}", e)),
    }
}

fn command_failure(command: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!(
        "{} exited with {}: {}",
        command,
        output.status,
        stderr.trim()
    )
}

/// Check if a path is tracked in version control (git or jj)
/// Returns VcsCheckResult indicating tracked, untracked, or error
pub fn is_tracked_in_vcs(path: &Path) -> VcsCheckResult {
    // First check if this is a file (tracked files must be files, not directories)
    if !path.is_file() {
        return VcsCheckResult::Untracked;
    }

    match detect_vcs(path) {
        (VcsType::Jujutsu, Some(root)) => is_tracked_in_jj(path, &root),
        (VcsType::Git, Some(root)) => is_tracked_in_git(path, &root),
        (VcsType::None, _) => VcsCheckResult::Untracked,
        (_, None) => VcsCheckResult::Unknown("VCS root was not found".to_string()),
    }
}

/// Spot-check: Does a directory contain ANY tracked files? (for Category 2 directories)
/// Returns Some(true) if tracked files exist, Some(false) if none, None on VCS error.
/// Uses early-exit optimization (head -1) to avoid scanning thousands of files.
pub fn has_tracked_files(dir: &Path, vcs_type: VcsType, vcs_root: &Path) -> Option<bool> {
    match vcs_type {
        VcsType::Git => {
            let relative_dir = dir.strip_prefix(vcs_root).ok()?;
            let output = Command::new("git")
                .arg("ls-files")
                .arg("--")
                .arg(relative_dir)
                .current_dir(vcs_root)
                .output();

            match output {
                Ok(output) if output.status.success() => Some(!output.stdout.is_empty()),
                Ok(_) | Err(_) => None,
            }
        }
        VcsType::Jujutsu => {
            let relative_dir = dir.strip_prefix(vcs_root).ok()?;

            let output = Command::new("jj")
                .arg("file")
                .arg("list")
                .arg(relative_dir)
                .current_dir(vcs_root)
                .output();

            match output {
                Ok(output) if output.status.success() => Some(!output.stdout.is_empty()),
                Ok(_) | Err(_) => None,
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
            let relative_dir = dir.strip_prefix(vcs_root).map_err(|error| {
                format!(
                    "{} is outside Git root {}: {}",
                    dir.display(),
                    vcs_root.display(),
                    error
                )
            })?;
            let output = Command::new("git")
                .arg("ls-files")
                .arg("--")
                .arg(relative_dir)
                .current_dir(vcs_root)
                .output()
                .map_err(|e| format!("git ls-files failed: {}", e))?;

            if !output.status.success() {
                return Err(command_failure("git ls-files", &output));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if !line.is_empty() {
                    tracked.insert(vcs_root.join(line));
                }
            }
        }
        VcsType::Jujutsu => {
            let relative_dir = dir.strip_prefix(vcs_root).map_err(|error| {
                format!(
                    "{} is outside Jujutsu root {}: {}",
                    dir.display(),
                    vcs_root.display(),
                    error
                )
            })?;

            let output = Command::new("jj")
                .arg("file")
                .arg("list")
                .arg(relative_dir)
                .current_dir(vcs_root)
                .output()
                .map_err(|e| format!("jj file list failed: {}", e))?;

            if !output.status.success() {
                return Err(command_failure("jj file list", &output));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if !line.is_empty() {
                    tracked.insert(vcs_root.join(line));
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
