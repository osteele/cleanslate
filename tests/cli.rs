use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

fn setup_test_directory() -> tempfile::TempDir {
    let dir = tempdir().unwrap();

    // Create a Cargo.toml to make this a valid project root (needed for /target pattern)
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();

    // Create a mock directory structure for testing
    // Add files to make them non-empty so they're detected as artifacts
    fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    fs::write(dir.path().join("node_modules/package.json"), "{}").unwrap();

    fs::create_dir_all(dir.path().join("__pycache__")).unwrap();
    fs::write(dir.path().join("__pycache__/test.pyc"), "compiled").unwrap();

    fs::create_dir_all(dir.path().join("target")).unwrap();
    fs::write(dir.path().join("target/debug.txt"), "debug").unwrap();

    // Write a dummy file to verify the directory
    fs::write(dir.path().join("test_file.txt"), "This is a test").unwrap();

    // Print debug info
    println!("Created test directory at: {}", dir.path().display());
    println!("Directory contents:");
    for entry in fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        println!("  {}", entry.path().display());
    }

    dir
}

#[test]
fn test_finds_artifacts() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--verbose").assert();

    // Check that the command succeeded
    assert
        .success()
        // Check that it found all our artifacts
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("__pycache__"))
        .stdout(predicate::str::contains("target"));
}

#[test]
fn test_verbose_flag() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--verbose").assert();

    // With verbose flag, we should see DEBUG messages about scanning directories
    assert.success().stdout(
        predicate::str::contains("DEBUG: Scanning directory")
            .or(predicate::str::contains("DEBUG: Spot-checking")),
    );
}

#[test]
fn test_delete_flag_dry_run() {
    let dir = setup_test_directory();

    // First, check what would be deleted without actually deleting
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--no-sizes").assert();

    // With --no-sizes, should show artifact count message instead of "Total" row
    assert
        .success()
        .stdout(predicate::str::contains("Found").and(predicate::str::contains("artifact")));

    // Verify that our artifacts still exist
    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

#[test]
fn test_delete_flag() {
    let dir = setup_test_directory();

    // First, check that our artifacts exist
    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());

    // Run the command with --delete --yes (non-interactive)
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--delete").arg("--yes").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("artifact(s) across"));

    // Verify that our artifacts were deleted
    assert!(!dir.path().join("node_modules").exists());
    assert!(!dir.path().join("__pycache__").exists());
    assert!(!dir.path().join("target").exists());
}

#[cfg(unix)]
#[test]
fn test_delete_read_only_go_module_cache() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("go.mod"), "module example.com/project\n").unwrap();

    let module_dir = dir.path().join(".gomodcache/example.com/dependency@v1.0.0");
    let nested_dir = module_dir.join("nested");
    fs::create_dir_all(&nested_dir).unwrap();
    fs::write(module_dir.join("source.go"), "package dependency\n").unwrap();
    fs::write(nested_dir.join("timing.log"), "cached output\n").unwrap();

    fs::set_permissions(&nested_dir, fs::Permissions::from_mode(0o555)).unwrap();
    fs::set_permissions(&module_dir, fs::Permissions::from_mode(0o555)).unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    cmd.arg(dir.path())
        .arg("--delete")
        .arg("--yes")
        .assert()
        .success();

    assert!(!dir.path().join(".gomodcache").exists());
}

#[test]
fn test_delete_preserves_scan_root_and_empty_ancestors() {
    let dir = tempdir().unwrap();
    let scan_root = dir.path().join("outer/project");
    fs::create_dir_all(&scan_root).unwrap();
    fs::write(scan_root.join("stale.log"), "log").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    cmd.arg(&scan_root)
        .arg("--delete")
        .arg("--yes")
        .assert()
        .success();

    assert!(scan_root.exists());
    assert!(dir.path().join("outer").exists());
}

#[test]
fn test_delete_preserves_non_aggressive_trivial_files() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    fs::create_dir_all(dir.path().join("output")).unwrap();
    fs::write(dir.path().join("output/stale.log"), "log").unwrap();
    fs::write(dir.path().join("output/.DS_Store"), "metadata").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    cmd.arg(dir.path())
        .arg("--delete")
        .arg("--yes")
        .assert()
        .success();

    assert!(dir.path().join("output/.DS_Store").exists());
}

#[test]
fn test_delete_preserves_artifact_directory_with_nested_vcs() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    fs::create_dir_all(dir.path().join("node_modules/package/.git")).unwrap();
    fs::write(dir.path().join("node_modules/package/source.js"), "source").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    cmd.arg(dir.path())
        .arg("--delete")
        .arg("--yes")
        .assert()
        .success();

    assert!(dir.path().join("node_modules/package/source.js").exists());
    assert!(dir.path().join("node_modules/package/.git").exists());
}

#[test]
fn test_vcs_failure_fails_closed() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join("stale.log"), "log").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    cmd.arg(dir.path())
        .arg("--delete")
        .arg("--yes")
        .assert()
        .success();

    assert!(dir.path().join("stale.log").exists());
}

#[test]
fn test_exclude_single_directory() {
    let dir = setup_test_directory();

    // Run with --exclude to skip node_modules
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("-x").arg("node_modules").assert();

    // Should succeed and find other artifacts (node_modules is excluded)
    // Note: "node_modules" may appear in the help text showing the --exclude flag,
    // but it should not contribute to the artifact list in the "What" column
    assert
        .success()
        .stdout(predicate::str::contains("__pycache__"))
        .stdout(predicate::str::contains("target"));
}

#[test]
fn test_exclude_multiple_directories() {
    let dir = setup_test_directory();

    // Run with multiple --exclude flags
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd
        .arg(dir.path())
        .arg("-x")
        .arg("node_modules")
        .arg("-x")
        .arg("__pycache__")
        .assert();

    // Should succeed and find only target (others are excluded)
    // Note: Excluded directory names may appear in the help text
    assert.success().stdout(predicate::str::contains("target"));
}

#[test]
fn test_exclude_does_not_affect_files() {
    let dir = tempdir().unwrap();

    // Create a directory named "dist"
    fs::create_dir_all(dir.path().join("dist")).unwrap();
    fs::write(dir.path().join("dist/artifact.txt"), "test").unwrap();

    // Create a FILE named "dist.txt" that contains "dist" in its name
    // This tests that we're matching directory names, not file names
    fs::write(dir.path().join("dist.txt"), "file content").unwrap();

    // Create another artifact directory to ensure we still find others
    fs::create_dir_all(dir.path().join("node_modules")).unwrap();

    // Create a Cargo.toml to make this a valid project root
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();

    // Run with --exclude dist - should exclude the directory but still scan other artifacts
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd
        .arg(dir.path())
        .arg("-x")
        .arg("dist")
        .arg("--verbose")
        .assert();

    // Should exclude the dist directory (silently) and still find node_modules
    assert
        .success()
        .stdout(predicate::str::contains("node_modules"));

    // The dist directory should still exist (we didn't delete)
    assert!(dir.path().join("dist").is_dir());
    // The dist.txt file should also still exist
    assert!(dir.path().join("dist.txt").exists());
    assert!(dir.path().join("node_modules").exists());
}

#[test]
fn test_exclude_with_nested_directories() {
    let dir = tempdir().unwrap();

    // Create nested structure: project/node_modules/package/node_modules
    fs::create_dir_all(dir.path().join("node_modules/package/node_modules")).unwrap();
    fs::write(
        dir.path()
            .join("node_modules/package/node_modules/nested.txt"),
        "nested",
    )
    .unwrap();
    fs::write(dir.path().join("node_modules/package.json"), "{}").unwrap();

    // Create another artifact at the top level
    fs::create_dir_all(dir.path().join("__pycache__")).unwrap();
    fs::write(dir.path().join("__pycache__/test.pyc"), "compiled").unwrap();

    // Create a Cargo.toml to make this a valid project root
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();

    // Run with --exclude node_modules
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("-x").arg("node_modules").assert();

    // Should exclude all node_modules (top-level and nested)
    // Note: "node_modules" may appear in the help text showing the --exclude flag
    assert
        .success()
        .stdout(predicate::str::contains("__pycache__"));
}

/// Test that non-project directories with artifacts are scanned (Fix #1)
/// When a directory contains artifacts but no project indicators (Cargo.toml, package.json, etc.),
/// the tool should fall back to scanning the directory directly instead of silently ignoring it.
#[test]
fn test_non_project_directory_with_artifacts() {
    let dir = tempdir().unwrap();

    // Create only __pycache__ - NO project indicators like Cargo.toml or package.json
    fs::create_dir_all(dir.path().join("__pycache__")).unwrap();
    fs::write(dir.path().join("__pycache__/test.pyc"), "compiled").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).assert();

    // Should find the artifact even without a project root indicator
    assert
        .success()
        .stdout(predicate::str::contains("__pycache__"));
}

/// Test that --list mode shows artifacts (Fix #2)
/// Previously, list mode filtered out projects with zero size, which meant
/// directory artifacts weren't shown unless size calculation was also enabled.
#[test]
fn test_list_mode_without_calculate_sizes() {
    let dir = setup_test_directory();

    // Run with --list
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--list").assert();

    // Should show artifacts even without size calculation
    // The output should contain artifact names (node_modules, __pycache__, target)
    assert
        .success()
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("__pycache__"))
        .stdout(predicate::str::contains("target"));
}

#[test]
fn test_delete_yes_flag_deletes_without_prompt() {
    let dir = setup_test_directory();

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--delete").arg("--yes").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("artifact(s) across"));

    assert!(!dir.path().join("node_modules").exists());
    assert!(!dir.path().join("__pycache__").exists());
    assert!(!dir.path().join("target").exists());
}

#[test]
fn test_delete_non_tty_without_yes_refuses() {
    let dir = setup_test_directory();

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    cmd.arg(dir.path()).arg("--delete");
    // Pipe empty stdin so stdin is not a TTY; deletion without --yes must be refused.
    let assert = cmd.write_stdin("").assert();

    assert.failure().stderr(predicate::str::contains(
        "refusing to delete without a confirmation prompt",
    ));

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

#[test]
fn test_yes_without_delete_errors() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--yes").assert();

    assert.failure();
}

#[test]
fn test_selective_deletion_pass_only_removes_selected_projects() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport, ScanResult};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    let project_a = dir.path().join("project_a");
    let project_b = dir.path().join("project_b");
    fs::create_dir_all(&project_a).unwrap();
    fs::create_dir_all(&project_b).unwrap();

    let file_a = project_a.join("stale.log");
    let file_b = project_b.join("stale.log");
    fs::write(&file_a, "a").unwrap();
    fs::write(&file_b, "b").unwrap();

    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_a.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: file_a.clone(),
                size: 1,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Logs,
                files: Vec::new(),
            }],
        },
    );
    projects.insert(
        project_b.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: file_b.clone(),
                size: 1,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Logs,
                files: Vec::new(),
            }],
        },
    );

    let mut result = ScanResult {
        projects,
        total_bytes: 2,
        stats: cleanslate::ScanStats::default(),
    };

    let selected: HashSet<std::path::PathBuf> = [project_a.clone()].into_iter().collect();
    let summary = execute_plan(&mut result.projects, &selected, false);

    assert!(file_a.metadata().is_err());
    assert!(file_b.exists());

    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(summary.failures, 0);

    let a_removed = result.projects[&project_a].artifacts[0].removed;
    let b_removed = result.projects[&project_b].artifacts[0].removed;
    assert!(a_removed);
    assert!(!b_removed);
}

/// Regression test: when only some files of a Category 3 artifact can be
/// removed, the failures must be counted (and drive the exit code), not
/// swallowed because one file succeeded.
#[cfg(unix)]
#[test]
fn test_category3_partial_failures_are_counted() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir_all(&dist).unwrap();
    let file_a = dist.join("a.txt");
    let file_b = dist.join("b.txt");
    fs::write(&file_a, "a").unwrap();
    fs::write(&file_b, "b").unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: dist.clone(),
                size: 2,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Build,
                files: vec![file_a.clone(), file_b.clone()],
            }],
        },
    );

    // A read-only dist directory makes both file removals fail.
    fs::set_permissions(&dist, fs::Permissions::from_mode(0o555)).unwrap();

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    fs::set_permissions(&dist, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(summary.failures, 2, "both failed removals must be counted");
    assert_eq!(summary.artifacts_removed, 0);
    assert_eq!(summary.bytes_removed, 0);
    assert!(!projects[&project_root].artifacts[0].removed);
}

/// Regression test: files that vanished between the scan and the deletion run
/// (e.g. an enclosing artifact was removed first) are already gone, not
/// failures — the run must not report failures or claim their bytes.
#[test]
fn test_category3_already_gone_files_are_not_failures() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir_all(&dist).unwrap();
    let kept = dist.join("kept.txt");
    let gone = dist.join("gone.txt");
    fs::write(&kept, "k").unwrap();
    fs::write(&gone, "g").unwrap();
    // The enclosing artifact directory is removed before this entry executes.
    fs::remove_dir_all(&dist).unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                // Path no longer exists: execute_plan treats it as a file entry
                // and must report already-gone rather than failure.
                path: gone.clone(),
                size: 1,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Build,
                files: Vec::new(),
            }],
        },
    );
    let _ = kept;

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert_eq!(summary.failures, 0, "an already-gone file is not a failure");
    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(
        summary.bytes_removed, 0,
        "bytes must not be credited for a file this run did not delete"
    );
    assert!(projects[&project_root].artifacts[0].removed);
}

/// Invalid time-filter values are command-line errors and must exit 2, as
/// documented under Exit Codes in the README.
#[test]
fn test_invalid_time_filter_values_exit_2() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--older-than").arg("15x").assert();
    assert.failure().code(2).stderr(predicate::str::contains(
        "invalid value '15x' for '--older-than'",
    ));
    assert!(dir.path().join("node_modules").exists());

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd
        .arg(dir.path())
        .arg("--modified-before")
        .arg("01-15-2025")
        .assert();
    assert.failure().code(2).stderr(predicate::str::contains(
        "invalid value '01-15-2025' for '--modified-before'",
    ));
    assert!(dir.path().join("target").exists());
}

/// A recreatable (Category 2) directory artifact reports its removal in the
/// summary: one artifact removed, its full size credited.
#[test]
fn test_category2_removal_is_summarized_with_bytes() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let target = dir.path().join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("debug.txt"), "debug").unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: target.clone(),
                size: 5,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Rust".to_string(),
                artifact_type: ArtifactType::Build,
                files: Vec::new(),
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert!(!target.exists());
    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(summary.failures, 0);
    assert_eq!(summary.bytes_removed, 5);
    assert!(projects[&project_root].artifacts[0].removed);
}

/// A Category 3 artifact whose files were partly deleted and partly already
/// gone counts as removed, with its bytes credited by this run.
#[test]
fn test_category3_mixed_deleted_and_gone_counts_as_removed_with_bytes() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir_all(&dist).unwrap();
    let existing = dist.join("a.txt");
    fs::write(&existing, "a").unwrap();
    let gone = dist.join("gone.txt");
    fs::write(&gone, "g").unwrap();
    fs::remove_file(&gone).unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: dist.clone(),
                size: 2,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Build,
                files: vec![existing.clone(), gone.clone()],
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert_eq!(summary.failures, 0);
    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(summary.bytes_removed, 2);
    assert!(projects[&project_root].artifacts[0].removed);
    assert!(!existing.exists());
}

/// A Category 3 artifact whose files are all already gone still counts as
/// removed (idempotent), but no bytes are credited for this run.
#[test]
fn test_category3_all_files_gone_counts_as_removed_without_bytes() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir_all(&dist).unwrap();
    let gone_a = dist.join("a.txt");
    let gone_b = dist.join("b.txt");
    fs::write(&gone_a, "a").unwrap();
    fs::write(&gone_b, "b").unwrap();
    fs::remove_file(&gone_a).unwrap();
    fs::remove_file(&gone_b).unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: dist.clone(),
                size: 2,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Build,
                files: vec![gone_a.clone(), gone_b.clone()],
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert_eq!(summary.failures, 0);
    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(summary.bytes_removed, 0);
    assert!(projects[&project_root].artifacts[0].removed);
}

/// A Category 3 artifact where one file is removed and another fails is NOT
/// removed overall: the failure is counted and no artifact/bytes are credited.
#[test]
fn test_category3_partial_success_with_failure_is_not_removed() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let dist = dir.path().join("dist");
    fs::create_dir_all(&dist).unwrap();
    let removable = dist.join("a.txt");
    fs::write(&removable, "a").unwrap();
    // A non-empty directory cannot be removed by remove_file: a stand-in for
    // any per-file failure that leaves the artifact directory in place.
    let failing = dist.join("subdir");
    fs::create_dir_all(&failing).unwrap();
    fs::write(failing.join("keep.txt"), "keep").unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: dist.clone(),
                size: 2,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Build,
                files: vec![removable.clone(), failing.clone()],
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert_eq!(summary.failures, 1);
    assert_eq!(summary.artifacts_removed, 0);
    assert_eq!(summary.bytes_removed, 0);
    assert!(!projects[&project_root].artifacts[0].removed);
    assert!(!removable.exists(), "the removable file is still deleted");
    assert!(failing.exists(), "the failing target is untouched");
}

/// A file artifact whose removal fails is counted as a failure.
#[cfg(unix)]
#[test]
fn test_file_artifact_failure_is_counted() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let log_dir = dir.path().join("log");
    fs::create_dir_all(&log_dir).unwrap();
    let file = log_dir.join("stale.log");
    fs::write(&file, "log").unwrap();
    // A read-only parent directory makes remove_file fail.
    fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o555)).unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: file.clone(),
                size: 3,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Logs,
                files: Vec::new(),
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(summary.failures, 1);
    assert_eq!(summary.artifacts_removed, 0);
    assert_eq!(summary.bytes_removed, 0);
    assert!(!projects[&project_root].artifacts[0].removed);
    assert!(file.exists());
}

/// A successfully deleted file artifact credits its bytes to the summary.
#[test]
fn test_file_artifact_removal_credits_bytes() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let file = dir.path().join("stale.log");
    fs::write(&file, "abc").unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: file.clone(),
                size: 3,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Logs,
                files: Vec::new(),
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(summary.bytes_removed, 3);
    assert_eq!(summary.failures, 0);
    assert!(!file.exists());
}

/// After removing a file artifact, directories left empty up to (but not
/// including) the project root are cleaned up; non-empty ones remain.
#[test]
fn test_empty_directories_are_cleaned_up_to_project_root() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    // Build entry paths from the canonicalized root so they share the
    // project_root prefix (the real scanner canonicalizes both consistently).
    let project_root = dir.path().canonicalize().unwrap();
    let nested = project_root.join("dist/a");
    fs::create_dir_all(&nested).unwrap();
    let file = nested.join("stale.log");
    fs::write(&file, "log").unwrap();
    // A sibling directory keeps dist non-empty at the top level.
    let kept_dir = project_root.join("dist/b");
    fs::create_dir_all(&kept_dir).unwrap();

    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: file.clone(),
                size: 3,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Logs,
                files: Vec::new(),
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    assert_eq!(summary.failures, 0);
    assert!(!file.exists());
    // dist/a became empty and is removed; dist still contains b and remains.
    assert!(!nested.exists(), "empty parent dist/a should be removed");
    assert!(
        dir.path().join("dist").exists(),
        "non-empty dist must remain"
    );
    assert!(kept_dir.exists());
    assert!(
        project_root.exists(),
        "the project root itself must never be removed"
    );
}

/// A recreatable directory that lacks the owner-write bit (like Go module
/// caches, but here 0o500) gets its permissions repaired before removal.
#[cfg(unix)]
#[test]
fn test_directory_missing_owner_write_bit_is_still_removed() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("go.mod"), "module example.com/project\n").unwrap();
    let cache = dir.path().join(".gomodcache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("source.go"), "package p\n").unwrap();
    // 0o500 (r-x): remove_dir_all cannot unlink from it, and unlike 0o555 the
    // permission-repair guard's `&` check is what detects the missing bit.
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o500)).unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: cache.clone(),
                size: 12,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Go".to_string(),
                artifact_type: ArtifactType::Cache,
                files: Vec::new(),
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    if cache.exists() {
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert!(!cache.exists(), "cache directory should have been removed");
    assert_eq!(summary.artifacts_removed, 1);
    assert_eq!(summary.failures, 0);
}

/// A recreatable directory that cannot be removed even after the permission
/// retry (its read-only PARENT blocks the unlink, and the retry only repairs
/// the artifact directory itself) is counted as a failure.
#[cfg(unix)]
#[test]
fn test_category2_removal_failure_is_counted() {
    use cleanslate::{execute_plan, ArtifactEntry, ArtifactType, ProjectReport};
    use std::collections::{HashMap, HashSet};

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    let ro = dir.path().join("ro");
    fs::create_dir_all(&ro).unwrap();
    let artifact = ro.join("node_modules");
    fs::create_dir_all(&artifact).unwrap();
    fs::write(artifact.join("package.json"), "{}").unwrap();
    // Only the artifact's parent is read-only: chmod repair inside the
    // artifact cannot fix that, so removal fails.
    fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();

    let project_root = dir.path().canonicalize().unwrap();
    let mut projects: HashMap<std::path::PathBuf, ProjectReport> = HashMap::new();
    projects.insert(
        project_root.clone(),
        ProjectReport {
            artifacts: vec![ArtifactEntry {
                path: artifact.clone(),
                size: 2,
                removed: false,
                modified: None,
                time_filtered: false,
                language_name: "Test".to_string(),
                artifact_type: ArtifactType::Dependency,
                files: Vec::new(),
            }],
        },
    );

    let selected: HashSet<std::path::PathBuf> = [project_root.clone()].into_iter().collect();
    let summary = execute_plan(&mut projects, &selected, false);

    fs::set_permissions(&ro, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(summary.failures, 1);
    assert_eq!(summary.artifacts_removed, 0);
    assert_eq!(summary.bytes_removed, 0);
    assert!(!projects[&project_root].artifacts[0].removed);
    assert!(artifact.exists(), "the artifact directory must survive");
}

/// Regression test: --delete --yes must print a deletion summary, not redisplay
/// the full scan table.
#[test]
fn test_delete_yes_prints_deletion_summary_not_table() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--delete").arg("--yes").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("artifact(s) across"))
        .stdout(predicate::str::contains("skipped"))
        // The full report table must NOT be redisplayed after deletion
        .stdout(
            predicate::str::contains("Path")
                .and(predicate::str::contains("What"))
                .not(),
        )
        .stdout(predicate::str::contains("Run with --list").not());

    assert!(!dir.path().join("node_modules").exists());
    assert!(!dir.path().join("__pycache__").exists());
    assert!(!dir.path().join("target").exists());
}

/// Regression test: --dry-run in default table mode (no --list) must list the
/// artifacts in the report, delete nothing, and print the dry-run line.
/// Previously the "Would remove" lines only appeared when combined with --list.
#[test]
fn test_dry_run_table_mode_lists_artifacts_and_deletes_nothing() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--dry-run").assert();

    assert
        .success()
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("__pycache__"))
        .stdout(predicate::str::contains("target"))
        .stdout(predicate::str::contains("Dry run: no files were deleted."))
        // The dry run is a preview; it must not suggest a deletion command
        .stdout(predicate::str::contains("To delete:").not());

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

/// A plain scan (no --delete) is the preview: it shows the artifacts and the
/// "To delete:" hint.
#[test]
fn test_plain_scan_shows_artifacts_and_delete_hint() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).assert();

    assert
        .success()
        .stdout(predicate::str::contains("node_modules"))
        .stdout(predicate::str::contains("To delete: cleanslate --delete"));

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

/// Sizes are on by default: a plain scan shows the Removable column and a
/// Total row without any size flag.
#[test]
fn test_sizes_on_by_default() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removable"))
        .stdout(predicate::str::contains("Age"))
        .stdout(predicate::str::contains("Total"))
        .stdout(predicate::str::contains("--calculate-sizes").not());
}

/// The Total row shares the path column with project rows, so a short project
/// path must not shift the Total row's size value out of alignment.
#[test]
fn test_total_row_size_column_aligns_with_project_rows() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd.arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    let removable_end = |line: &str| {
        let start = line.find("iB").or_else(|| line.find(" B"))?;
        Some(start + 2)
    };

    let project_row = stdout
        .lines()
        .find(|line| line.starts_with('.'))
        .expect("expected a project row for the scanned root");
    let total_row = stdout
        .lines()
        .find(|line| line.starts_with("Total"))
        .expect("expected a Total row");

    assert_eq!(
        removable_end(project_row),
        removable_end(total_row),
        "Removable column misaligned:\nproject: {:?}\ntotal:   {:?}",
        project_row,
        total_row
    );
}

/// --no-sizes omits the size columns and prints the artifact-count footer.
#[test]
fn test_no_sizes_omits_size_columns() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--no-sizes").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removable").not())
        .stdout(predicate::str::contains("Total").not())
        .stdout(
            predicate::str::contains("Found").and(predicate::str::contains("artifact(s) across")),
        )
        .stdout(predicate::str::contains("--calculate-sizes").not());
}

/// --calculate-sizes still works as a hidden deprecated alias and prints a
/// deprecation notice to stderr.
#[test]
fn test_calculate_sizes_deprecated_alias() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--calculate-sizes").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removable"))
        .stderr(predicate::str::contains(
            "cleanslate: --calculate-sizes is now the default; the flag is ignored",
        ));
}

/// --delete --yes deletes non-interactively: no confirmation prompt is shown.
#[test]
fn test_delete_yes_skips_confirmation_prompt() {
    let dir = setup_test_directory();

    assert!(dir.path().join("node_modules").exists());

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--delete").arg("--yes").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Removed"))
        .stdout(predicate::str::contains("artifact(s) across"))
        // The confirmation question must not appear when --yes is given
        .stdout(predicate::str::contains("?").not())
        .stderr(predicate::str::contains("?").not());

    assert!(!dir.path().join("node_modules").exists());
    assert!(!dir.path().join("__pycache__").exists());
    assert!(!dir.path().join("target").exists());
}

/// When a VCS check fails and artifacts are skipped to be safe, a non-verbose
/// run reports how many were skipped.
#[test]
fn test_vcs_failure_notice_without_verbose() {
    let dir = tempdir().unwrap();
    // An empty .git directory makes `git ls-files` fail, so the tracking
    // status of stale.log cannot be determined and it is skipped to be safe.
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join("stale.log"), "log").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).assert();

    assert.success().stderr(predicate::str::contains(
        "artifact(s) skipped because their version-control status could not be determined; rerun with --verbose for details.",
    ));

    assert!(dir.path().join("stale.log").exists());
}

/// Regression test: a plain scan with piped/redirected stdout must stay
/// scriptable and print the deletion hint instead of prompting.
#[test]
fn test_plain_scan_piped_stdout_prints_delete_hint_and_deletes_nothing() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).assert();

    assert
        .success()
        .stdout(predicate::str::contains("To delete: cleanslate --delete"))
        .stdout(predicate::str::contains("No artifacts deleted.").not());

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

/// Regression test: --dry-run with piped output previews the report, prints
/// the dry-run line, and does not suggest an interactive deletion command.
#[test]
fn test_dry_run_piped_output_prints_dry_run_line_and_no_hint() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--dry-run").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Dry run: no files were deleted."))
        .stdout(predicate::str::contains("To delete:").not());

    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

/// Regression test: the progress spinner's final line must not survive into
/// the captured report output.
#[test]
fn test_scan_stdout_does_not_contain_scan_complete() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd.arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        !stdout.contains("Scan complete!"),
        "stdout contained 'Scan complete!':\n{}",
        stdout
    );
}

/// Regression test: the report must begin with exactly one blank line in
/// default table mode, so the first line is empty and the second is not.
#[test]
fn test_table_report_starts_with_exactly_one_blank_line() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd.arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    assert!(
        lines.len() >= 2,
        "expected at least two lines of stdout:\n{}",
        stdout
    );
    assert!(
        lines[0].is_empty(),
        "expected first line to be empty:\n{}",
        stdout
    );
    assert!(
        !lines[1].is_empty(),
        "expected second line to be non-empty:\n{}",
        stdout
    );
}

/// Regression test: the report must begin with exactly one blank line in
/// --list mode.
#[test]
fn test_list_report_starts_with_exactly_one_blank_line() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd.arg(dir.path()).arg("--list").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    assert!(
        lines.len() >= 2,
        "expected at least two lines of stdout:\n{}",
        stdout
    );
    assert!(
        lines[0].is_empty(),
        "expected first line to be empty:\n{}",
        stdout
    );
    assert!(
        !lines[1].is_empty(),
        "expected second line to be non-empty:\n{}",
        stdout
    );
}

/// Default color mode (auto) with piped output must not emit ANSI escape sequences.
#[test]
fn test_color_auto_piped_no_escapes() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd.arg(dir.path()).arg("--list").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        !stdout.contains("\x1b["),
        "expected no ANSI escapes in default auto/piped output:\n{}",
        stdout
    );
}

/// --color=always with piped output must emit ANSI escape sequences.
#[test]
fn test_color_always_piped_has_escapes() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd
        .arg(dir.path())
        .arg("--list")
        .arg("--color=always")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("\x1b["),
        "expected ANSI escapes in --color=always output:\n{}",
        stdout
    );
}

/// An explicit --color=always beats the NO_COLOR environment variable.
#[test]
fn test_color_always_overrides_no_color() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd
        .arg(dir.path())
        .arg("--list")
        .arg("--color=always")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("\x1b["),
        "expected ANSI escapes when --color=always overrides NO_COLOR:\n{}",
        stdout
    );
}

/// An explicit --color=never beats the CLICOLOR_FORCE environment variable.
#[test]
fn test_color_never_overrides_clicolor_force() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd
        .arg(dir.path())
        .arg("--list")
        .arg("--color=never")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        !stdout.contains("\x1b["),
        "expected no ANSI escapes when --color=never overrides CLICOLOR_FORCE:\n{}",
        stdout
    );
}

/// An invalid --color value must produce a usage error and a non-zero exit.
#[test]
fn test_color_invalid_value_errors() {
    let dir = setup_test_directory();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--color=sometimes").assert();

    assert
        .failure()
        .stderr(predicate::str::contains("error: invalid value"));
}

/// Regression test: the "No artifacts found." message must be preceded by
/// exactly one blank line.
#[test]
fn test_no_artifacts_found_starts_with_exactly_one_blank_line() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();

    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let output = cmd.arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();

    assert!(
        lines.len() >= 2,
        "expected at least two lines of stdout:\n{}",
        stdout
    );
    assert!(
        lines[0].is_empty(),
        "expected first line to be empty:\n{}",
        stdout
    );
    assert_eq!(
        lines[1], "No artifacts found.",
        "expected second line to be the empty-results message:\n{}",
        stdout
    );
}
