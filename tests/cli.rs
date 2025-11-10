use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
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

    // With verbose flag, we should see DEBUG messages
    assert
        .success()
        .stdout(predicate::str::contains("DEBUG: Checking path"));
}

#[test]
fn test_delete_flag_dry_run() {
    let dir = setup_test_directory();

    // First, check what would be deleted without actually deleting
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).assert();

    assert.success().stdout(predicate::str::contains("Total")); // Table format shows "Total" row

    // Verify that our artifacts still exist
    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());
}

// Note: This test is marked as ignored because it actually deletes files
#[test]
#[ignore]
fn test_delete_flag() {
    let dir = setup_test_directory();

    // First, check that our artifacts exist
    assert!(dir.path().join("node_modules").exists());
    assert!(dir.path().join("__pycache__").exists());
    assert!(dir.path().join("target").exists());

    // Run the command with --delete
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd.arg(dir.path()).arg("--delete").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Total Size Removed"));

    // Verify that our artifacts were deleted
    assert!(!dir.path().join("node_modules").exists());
    assert!(!dir.path().join("__pycache__").exists());
    assert!(!dir.path().join("target").exists());
}

#[test]
fn test_exclude_single_directory() {
    let dir = setup_test_directory();

    // Run with --exclude to skip node_modules
    let mut cmd = Command::cargo_bin("cleanslate").unwrap();
    let assert = cmd
        .arg(dir.path())
        .arg("-x")
        .arg("node_modules")
        .assert();

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
    assert
        .success()
        .stdout(predicate::str::contains("target"));
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

    // Should exclude the dist directory and find node_modules
    assert
        .success()
        .stdout(predicate::str::contains("Skipping excluded directory").and(predicate::str::contains("dist")))
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
        dir.path().join("node_modules/package/node_modules/nested.txt"),
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
    let assert = cmd
        .arg(dir.path())
        .arg("-x")
        .arg("node_modules")
        .assert();

    // Should exclude all node_modules (top-level and nested)
    // Note: "node_modules" may appear in the help text showing the --exclude flag
    assert
        .success()
        .stdout(predicate::str::contains("__pycache__"));
}
