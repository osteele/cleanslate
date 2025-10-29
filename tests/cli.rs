use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn setup_test_directory() -> tempfile::TempDir {
    let dir = tempdir().unwrap();

    // Create a mock directory structure for testing
    fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    fs::create_dir_all(dir.path().join("__pycache__")).unwrap();
    fs::create_dir_all(dir.path().join("target")).unwrap();

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

    assert
        .success()
        .stdout(predicate::str::contains("Total Size Found"));

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
