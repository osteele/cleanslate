//! Plan execution: the only stage that deletes artifacts.

use crate::scanner::ProjectReport;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Outcome of executing a deletion plan
#[derive(Debug, Default)]
pub struct ExecutionSummary {
    /// Number of artifact entries actually removed
    pub artifacts_removed: usize,
    /// Total size of removed artifacts (only meaningful when sizes were calculated)
    pub bytes_removed: u64,
    /// Number of artifact entries whose removal failed
    pub failures: usize,
}

/// Make a vetted recreatable directory removable by its owner without following symlinks.
/// Go module caches make downloaded directories read-only, which prevents remove_dir_all
/// even though every file in the cache is disposable.
fn make_tree_removable(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() {
        return Ok(());
    }

    if metadata.is_dir() {
        make_directory_removable(path, &metadata)?;
        for entry in fs::read_dir(path)? {
            make_tree_removable(&entry?.path())?;
        }
    } else {
        make_file_removable(path, &metadata)?;
    }

    Ok(())
}

#[cfg(unix)]
fn make_directory_removable(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = metadata.permissions();
    let mode = permissions.mode();
    if mode & 0o700 != 0o700 {
        permissions.set_mode(mode | 0o700);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn make_directory_removable(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    make_file_removable(path, metadata)
}

#[cfg(unix)]
fn make_file_removable(_path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

// On Windows the read-only attribute is the only permission bit; clearing it
// is exactly the intent here. The lint's Unix world-writable concern cannot
// apply — this function only exists on non-Unix targets.
#[cfg(not(unix))]
#[allow(clippy::permissions_set_readonly_false)]
fn make_file_removable(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn remove_recreatable_dir(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        // A vanished path is already in the desired state; treating it as an
        // error would turn an overlapping removal into a false failure.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            make_tree_removable(path)?;
            fs::remove_dir_all(path)
        }
        result => result,
    }
}

/// Outcome of attempting to remove one file or directory artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemovalOutcome {
    /// Removed by this run.
    Deleted,
    /// Already gone before this run attempted it (e.g. an enclosing artifact
    /// that contained it was removed first). Not an error, and its bytes were
    /// not freed by this entry.
    AlreadyGone,
    /// Removal was attempted and failed.
    Failed,
}

/// Remove a single file artifact, logging per-file errors.
fn remove_file_artifact(path: &Path, verbose: bool) -> RemovalOutcome {
    match fs::remove_file(path) {
        Ok(_) => {
            if verbose {
                println!("Removed: {}", path.display());
            }
            RemovalOutcome::Deleted
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if verbose {
                println!("Already gone: {}", path.display());
            }
            RemovalOutcome::AlreadyGone
        }
        Err(err) => {
            eprintln!("Error removing {}: {}. Skipping.", path.display(), err);
            RemovalOutcome::Failed
        }
    }
}

/// Remove a recreatable (Category 2) directory artifact.
fn remove_recreatable_artifact(path: &Path, verbose: bool) -> RemovalOutcome {
    match remove_recreatable_dir(path) {
        Ok(_) => {
            if verbose {
                println!("Removed directory: {}", path.display());
            }
            RemovalOutcome::Deleted
        }
        Err(err) => {
            eprintln!("Error removing {}: {}", path.display(), err);
            RemovalOutcome::Failed
        }
    }
}

/// Outcome of removing the untracked files of a Category 3 (mixed) directory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Category3Outcome {
    deleted: usize,
    already_gone: usize,
    failed: usize,
}

impl Category3Outcome {
    fn any_target_processed(&self) -> bool {
        self.deleted + self.already_gone > 0
    }
}

/// Remove a Category 3 (mixed) directory artifact by removing its untracked files.
fn remove_category3_artifact(files: &[PathBuf], verbose: bool) -> Category3Outcome {
    let mut outcome = Category3Outcome::default();
    for file_path in files {
        match remove_file_artifact(file_path, verbose) {
            RemovalOutcome::Deleted => outcome.deleted += 1,
            RemovalOutcome::AlreadyGone => outcome.already_gone += 1,
            RemovalOutcome::Failed => outcome.failed += 1,
        }
    }
    outcome
}

/// Execute the deletion plan: remove artifacts belonging to the selected projects,
/// then clean up directories left empty. This is the only code that deletes.
/// Updates `entry.removed` for each artifact actually removed.
pub fn execute_plan(
    projects: &mut HashMap<PathBuf, ProjectReport>,
    selected_projects: &HashSet<PathBuf>,
    verbose: bool,
) -> ExecutionSummary {
    let mut summary = ExecutionSummary::default();

    for (project_path, project_report) in projects.iter_mut() {
        if !selected_projects.contains(project_path) {
            continue;
        }
        for entry in &mut project_report.artifacts {
            if entry.time_filtered {
                continue;
            }
            if entry.path.is_dir() {
                if entry.files.is_empty() {
                    match remove_recreatable_artifact(&entry.path, verbose) {
                        RemovalOutcome::Deleted => {
                            entry.removed = true;
                            summary.artifacts_removed += 1;
                            summary.bytes_removed += entry.size;
                        }
                        RemovalOutcome::AlreadyGone => {
                            entry.removed = true;
                            summary.artifacts_removed += 1;
                        }
                        RemovalOutcome::Failed => {
                            entry.removed = false;
                            summary.failures += 1;
                        }
                    }
                } else {
                    let outcome = remove_category3_artifact(&entry.files, verbose);
                    summary.failures += outcome.failed;
                    // The entry counts as removed only when every target file is
                    // gone; partial failures leave it in place for reporting.
                    entry.removed = outcome.failed == 0 && outcome.any_target_processed();
                    if entry.removed {
                        summary.artifacts_removed += 1;
                        // Bytes are credited only when this run deleted at least
                        // one file; fully-already-gone entries were freed elsewhere.
                        if outcome.deleted > 0 {
                            summary.bytes_removed += entry.size;
                        }
                    }
                }
            } else {
                match remove_file_artifact(&entry.path, verbose) {
                    RemovalOutcome::Deleted => {
                        entry.removed = true;
                        summary.artifacts_removed += 1;
                        summary.bytes_removed += entry.size;
                    }
                    RemovalOutcome::AlreadyGone => {
                        entry.removed = true;
                        summary.artifacts_removed += 1;
                    }
                    RemovalOutcome::Failed => {
                        entry.removed = false;
                        summary.failures += 1;
                    }
                }
            }
        }
    }

    cleanup_empty_directories(projects, verbose);

    summary
}

/// Remove empty directories after artifact deletion
fn cleanup_empty_directories(projects: &HashMap<PathBuf, ProjectReport>, verbose: bool) {
    // Collect all directories to check - both artifact dirs and parent dirs of removed files
    let mut dirs_to_check: HashSet<PathBuf> = HashSet::new();

    for (project_root, project_report) in projects {
        for entry in &project_report.artifacts {
            if entry.removed {
                let mut current = if entry.path.is_dir() {
                    Some(entry.path.as_path())
                } else {
                    entry.path.parent()
                };

                while let Some(dir) = current {
                    if dir == project_root || !dir.starts_with(project_root) {
                        break;
                    }
                    dirs_to_check.insert(dir.to_path_buf());
                    current = dir.parent();
                }
            }
        }
    }

    // Sort directories by depth (deepest first) so we remove child dirs before parents
    let mut dirs_vec: Vec<PathBuf> = dirs_to_check.into_iter().collect();
    dirs_vec.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    // Try to remove empty directories
    // Only remove genuinely empty directories. Other files may be tracked or intentionally kept.
    for dir in dirs_vec {
        // Skip if doesn't exist
        if !dir.exists() {
            continue;
        }

        // Check whether the directory is empty
        match fs::read_dir(&dir) {
            Ok(entries) => {
                // Collect all entries
                let remaining: Vec<_> = entries.filter_map(|e| e.ok()).collect();

                if remaining.is_empty() {
                    match fs::remove_dir(&dir) {
                        Ok(_) => {
                            if verbose {
                                println!("Removed empty directory: {}", dir.display());
                            }
                        }
                        Err(err) => {
                            if verbose {
                                eprintln!(
                                    "Warning: Failed to remove directory {}: {}",
                                    dir.display(),
                                    err
                                );
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
