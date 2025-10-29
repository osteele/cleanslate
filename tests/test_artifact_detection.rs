use crate::main::{get_artifact_patterns, is_artifact, ArtifactPattern};
use std::path::Path;

#[path = "../src/main.rs"]
mod main;

#[test]
fn test_is_artifact() {
    // Load patterns once and unwrap/expect
    let patterns = get_artifact_patterns().expect("Failed to load artifact patterns for test");

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
    assert!(is_artifact(Path::new("/some/path/target"), &patterns));
    assert!(
        is_artifact(Path::new("/some/path/Cargo.lock"), &patterns),
        "Cargo.lock should be detected as an artifact"
    );

    // Ruby artifacts
    assert!(is_artifact(Path::new("/some/path/bin"), &patterns));
    assert!(is_artifact(Path::new("/some/path/vendor"), &patterns));

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
    // This test is more conceptual since we can't easily create actual files
    // In a real project, you might use a temporary directory for this test

    // We can still test the logic that if no project root is found, the original path is returned
    let test_path = Path::new("/some/non/existent/path");
    let root = main::find_project_root(test_path);

    assert!(root.is_some());
    assert_eq!(root.unwrap(), test_path);
}
