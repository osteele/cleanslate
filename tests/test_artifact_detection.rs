use cleanslate::{find_project_root, get_artifact_patterns, is_artifact, is_recreatable_dir};
use std::path::Path;

#[test]
fn test_is_artifact() {
    // Load patterns once and unwrap/expect
    let patterns = get_artifact_patterns(true).expect("Failed to load artifact patterns for test");

    // Python artifacts
    assert!(
        is_artifact(Path::new("/some/path/__pycache__"), &patterns),
        "__pycache__ should be detected as an artifact"
    );
    assert!(
        is_artifact(Path::new("/some/path/.pytest_cache"), &patterns),
        ".pytest_cache should be detected as an artifact"
    );
    assert!(
        is_artifact(Path::new("/some/path/my_package.egg-info"), &patterns),
        ".egg-info should be detected as an artifact"
    );
    assert!(
        is_artifact(Path::new("/some/path/file.pyc"), &patterns),
        ".pyc should be detected as an artifact"
    );

    // Node.js artifacts
    assert!(
        is_artifact(Path::new("/some/path/node_modules"), &patterns),
        "node_modules should be detected as an artifact"
    );
    assert!(is_artifact(Path::new("/some/path/.next"), &patterns));
    assert!(
        is_artifact(Path::new("/some/path/yarn-error.log"), &patterns),
        "yarn-error.log should be detected as an artifact"
    );

    // Rust artifacts
    // Note: target now requires / prefix, so this should NOT match
    assert!(!is_artifact(Path::new("/some/path/target"), &patterns));
    // But at project root it should match
    // (This test is limited since we don't have a real project structure)

    // Ruby artifacts
    // Note: generic 'bin' pattern was removed to avoid false positives like .bun/bin
    assert!(!is_artifact(Path::new("/some/path/bin"), &patterns));
    // vendor should still match at project root
    assert!(!is_artifact(Path::new("/some/path/vendor"), &patterns));

    // Go artifacts
    assert!(
        is_artifact(Path::new("/some/path/.DS_Store"), &patterns),
        ".DS_Store should be detected as an artifact"
    );
    assert!(is_artifact(Path::new("/some/path/tmp"), &patterns));
    assert!(is_artifact(Path::new("/some/path/logs"), &patterns));

    // Non-artifacts
    assert!(!is_artifact(Path::new("/some/path/src"), &patterns));
    assert!(
        !is_artifact(Path::new("/some/path/README.md"), &patterns),
        "README.md should not be detected as an artifact"
    );
    assert!(
        !is_artifact(Path::new("/some/path/main.rs"), &patterns),
        "main.rs should not be detected as an artifact"
    );
    assert!(
        !is_artifact(Path::new("/some/path/config.toml"), &patterns),
        "config.toml should not be detected as an artifact"
    );
}

#[test]
fn test_find_project_root() {
    use std::env;
    use std::fs;

    // Create a temporary directory for testing
    let temp_dir = env::temp_dir().join("cleanslate_test");
    fs::create_dir_all(&temp_dir).ok();

    // Test 1: Directory without project root returns itself
    let test_dir = temp_dir.join("some_dir");
    fs::create_dir_all(&test_dir).ok();
    let root = find_project_root(&test_dir);
    assert!(root.is_some());
    assert_eq!(root.unwrap(), test_dir);

    // Test 2: File without project root returns parent directory
    let test_file = test_dir.join("file.txt");
    fs::write(&test_file, "test").ok();
    let root = find_project_root(&test_file);
    assert!(root.is_some());
    assert_eq!(root.unwrap(), test_dir);

    // Test 3: With a project root indicator
    let project_dir = temp_dir.join("project");
    fs::create_dir_all(&project_dir).ok();
    fs::write(project_dir.join("Cargo.toml"), "test").ok();

    let nested_file = project_dir.join("src/main.rs");
    fs::create_dir_all(nested_file.parent().unwrap()).ok();
    fs::write(&nested_file, "test").ok();

    let root = find_project_root(&nested_file);
    assert!(root.is_some());
    assert_eq!(root.unwrap(), project_dir);

    // Cleanup
    fs::remove_dir_all(&temp_dir).ok();
}

#[test]
fn test_pattern_prefix_behavior() {
    // This test verifies that patterns with / prefix only match at project root
    // while patterns without / match anywhere in the path

    let patterns = get_artifact_patterns(true).expect("Failed to load artifact patterns for test");

    // Patterns WITH / prefix should only match at project root
    // We can't fully test this without a real project structure, but we can verify
    // that the patterns are loaded correctly

    // Patterns WITHOUT / prefix should match anywhere
    assert!(
        is_artifact(Path::new("/some/path/logs"), &patterns),
        "logs (no prefix) should match anywhere"
    );
    assert!(
        is_artifact(Path::new("/some/path/nested/logs"), &patterns),
        "logs (no prefix) should match in nested paths"
    );

    assert!(
        is_artifact(Path::new("/some/path/tmp"), &patterns),
        "tmp (no prefix) should match anywhere"
    );
    assert!(
        is_artifact(Path::new("/some/deeply/nested/tmp"), &patterns),
        "tmp (no prefix) should match in deeply nested paths"
    );

    // .DS_Store should match anywhere (no prefix)
    assert!(
        is_artifact(Path::new("/some/path/.DS_Store"), &patterns),
        ".DS_Store should match anywhere"
    );
    assert!(
        is_artifact(Path::new("/some/nested/path/.DS_Store"), &patterns),
        ".DS_Store should match in nested paths"
    );
}

// ============ is_recreatable_dir tests ============

#[test]
fn test_is_recreatable_dir_node_modules() {
    assert!(
        is_recreatable_dir(Path::new("/some/path/node_modules")),
        "node_modules should be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_venv() {
    assert!(
        is_recreatable_dir(Path::new("/some/path/.venv")),
        ".venv should be recreatable"
    );
    assert!(
        is_recreatable_dir(Path::new("/some/path/venv")),
        "venv should be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_target() {
    assert!(
        is_recreatable_dir(Path::new("/some/path/target")),
        "target should be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_pycache() {
    assert!(
        is_recreatable_dir(Path::new("/some/path/__pycache__")),
        "__pycache__ should be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_src_not_recreatable() {
    assert!(
        !is_recreatable_dir(Path::new("/some/path/src")),
        "src should NOT be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_multi_component() {
    // vendor/bundle is a multi-component pattern
    assert!(
        is_recreatable_dir(Path::new("/project/vendor/bundle")),
        "vendor/bundle should be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_false_positive_check() {
    // /catalogs/bundle should NOT match vendor/bundle pattern
    assert!(
        !is_recreatable_dir(Path::new("/catalogs/bundle")),
        "catalogs/bundle should NOT be detected as recreatable (false positive)"
    );
    // but just "bundle" alone isn't in the list either
    assert!(
        !is_recreatable_dir(Path::new("/some/bundle")),
        "bundle alone should NOT be recreatable"
    );
}

#[test]
fn test_is_recreatable_dir_cache_directories() {
    assert!(is_recreatable_dir(Path::new("/path/.cache")));
    assert!(is_recreatable_dir(Path::new("/path/.pytest_cache")));
    assert!(is_recreatable_dir(Path::new("/path/.mypy_cache")));
    assert!(is_recreatable_dir(Path::new("/path/.ruff_cache")));
}
