use std::env;
use std::fs;
use std::path::PathBuf;

// Helper function to create a temporary directory structure for testing
fn create_test_directory() -> Result<PathBuf, std::io::Error> {
    let tempdir = env::temp_dir().join("cleanslate_test");

    if tempdir.exists() {
        fs::remove_dir_all(&tempdir)?;
    }

    fs::create_dir_all(&tempdir)?;

    // Create a mock project structure

    // Python project
    let python_dir = tempdir.join("python_project");
    fs::create_dir_all(&python_dir)?;
    fs::write(
        python_dir.join("pyproject.toml"),
        b"[tool.poetry]\nname = \"test\"\n",
    )?;

    // Python artifacts
    fs::create_dir_all(python_dir.join("__pycache__"))?;
    fs::create_dir_all(python_dir.join(".pytest_cache"))?;
    fs::create_dir_all(python_dir.join("dist"))?;
    fs::write(python_dir.join("file.pyc"), b"python bytecode")?;

    // JavaScript project
    let js_dir = tempdir.join("js_project");
    fs::create_dir_all(&js_dir)?;
    fs::write(js_dir.join("package.json"), b"{\n  \"name\": \"test\"\n}")?;

    // JavaScript artifacts
    fs::create_dir_all(js_dir.join("node_modules"))?;
    fs::create_dir_all(js_dir.join("dist"))?;
    fs::write(js_dir.join("yarn-error.log"), b"error log")?;

    // Rust project
    let rust_dir = tempdir.join("rust_project");
    fs::create_dir_all(&rust_dir)?;
    fs::write(rust_dir.join("Cargo.toml"), b"[package]\nname = \"test\"\n")?;

    // Rust artifacts
    fs::create_dir_all(rust_dir.join("target").join("debug"))?;
    fs::write(rust_dir.join("Cargo.lock"), b"lockfile")?;

    // Also add a .gitignore to test that it's respected
    fs::write(tempdir.join(".gitignore"), b"ignored_dir/\n")?;

    // Create an ignored directory that should be skipped
    fs::create_dir_all(tempdir.join("ignored_dir"))?;
    fs::create_dir_all(tempdir.join("ignored_dir").join("node_modules"))?; // This should be ignored

    Ok(tempdir)
}

// This test needs to be run manually with --test-threads=1 because it modifies the filesystem
// cargo test -- --test-threads=1
#[test]
#[ignore] // Ignore by default to avoid filesystem modifications during normal test runs
fn test_scan_artifacts_integration() {
    // This is a placeholder for a real integration test
    // In a real test, you would:
    // 1. Create a temporary directory structure with known artifacts
    // 2. Run the scan_for_artifacts function on that directory
    // 3. Verify the correct artifacts are found
    // 4. Optionally test the --delete functionality

    println!("To run a full integration test:");
    println!("cargo test test_scan_artifacts_integration -- --ignored");

    // Create a temporary test directory
    let test_dir = match create_test_directory() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("Failed to create test directory: {}", e);
            return;
        }
    };

    println!("Created test directory at: {}", test_dir.display());

    // In a real test, you would now call scan_for_artifacts and verify the results

    // Clean up
    if let Err(e) = fs::remove_dir_all(&test_dir) {
        eprintln!("Warning: Failed to clean up test directory: {}", e);
    }
}
