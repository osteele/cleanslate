//! VCS detection and tracking checks for Git and Jujutsu.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

/// Optional metrics for VCS operations.
/// In test builds this tracks how many batch VCS calls are issued so callers
/// can assert the subprocess count is O(1) per project.
#[derive(Default, Clone)]
pub struct VcsMetrics {
    batch_call_count: Arc<AtomicUsize>,
}

impl VcsMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn batch_call_count(&self) -> usize {
        self.batch_call_count.load(Ordering::SeqCst)
    }

    fn record_batch_call(&self) {
        self.batch_call_count.fetch_add(1, Ordering::SeqCst);
    }
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

fn command_failure(command: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!(
        "{} exited with {}: {}",
        command,
        output.status,
        stderr.trim()
    )
}

/// Batch-check: Get all tracked files in a directory (for Category 3 directories)
/// Returns Ok(HashSet) of tracked file paths, or Err(String) if VCS command failed.
pub fn get_tracked_files_batch(
    dir: &Path,
    vcs_type: VcsType,
    vcs_root: &Path,
    metrics: &VcsMetrics,
) -> Result<HashSet<PathBuf>, String> {
    metrics.record_batch_call();

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
            // When the directory is the repository root, strip_prefix returns an empty
            // path; git requires "." to mean "the whole repository".
            let relative_dir = if relative_dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative_dir
            };
            // -z emits NUL-separated raw paths. The default line format C-quotes
            // paths containing `"`/`\`/control characters (and non-ASCII under the
            // default core.quotePath=true), which would make tracked files miss
            // the HashSet and be misclassified as untracked.
            let output = Command::new("git")
                .arg("ls-files")
                .arg("-z")
                .arg("--")
                .arg(relative_dir)
                .current_dir(vcs_root)
                .output()
                .map_err(|e| format!("git ls-files failed: {}", e))?;

            if !output.status.success() {
                return Err(command_failure("git ls-files", &output));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.split('\0') {
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
            // When the directory is the repository root, strip_prefix returns an empty
            // path; jj requires "." to mean "the whole repository".
            let relative_dir = if relative_dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                relative_dir
            };

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
