use cleanslate::{get_artifact_patterns, scan_single_path, ScanOptions, TimeFilter};
use filetime::{set_file_mtime, FileTime};
use std::fs;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

fn ten_days_ago() -> SystemTime {
    SystemTime::now() - Duration::from_secs(10 * 24 * 60 * 60)
}

fn older_than_five_days() -> TimeFilter {
    TimeFilter::from_args(Some("5d"), None).unwrap()
}

#[test]
fn file_artifacts_use_one_vcs_batch_call_per_project() {
    use std::process::Command;

    let dir = tempdir().unwrap();

    // Initialize a real Git repository.
    Command::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .expect("git init failed");
    Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(dir.path())
        .output()
        .expect("git config user.email failed");
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()
        .expect("git config user.name failed");

    // Track one .aux file.
    fs::write(dir.path().join("tracked.aux"), "tracked").unwrap();
    Command::new("git")
        .args(["add", "tracked.aux"])
        .current_dir(dir.path())
        .output()
        .expect("git add failed");
    Command::new("git")
        .args(["commit", "-m", "track"])
        .current_dir(dir.path())
        .output()
        .expect("git commit failed");

    // Create 50 untracked .aux files.
    for i in 0..50 {
        fs::write(dir.path().join(format!("untracked{}.aux", i)), "untracked").unwrap();
    }

    let patterns = get_artifact_patterns(false).unwrap();
    let options = ScanOptions {
        verbose: false,
        calculate_sizes: false,
    };
    let result = scan_single_path(
        dir.path().to_str().unwrap(),
        &patterns,
        &[],
        options,
        &TimeFilter::from_args(None, None).unwrap(),
    )
    .unwrap();

    // The tracked file should be kept; only the 50 untracked files are reported.
    let aux_artifacts: Vec<_> = result
        .projects
        .values()
        .flat_map(|r| &r.artifacts)
        .filter(|a| a.path.extension().is_some_and(|e| e == "aux"))
        .collect();
    assert_eq!(
        aux_artifacts.len(),
        50,
        "all untracked .aux files should be reported"
    );
    assert!(
        !aux_artifacts
            .iter()
            .any(|a| a.path.file_name().unwrap() == "tracked.aux"),
        "tracked .aux file should not be reported for removal"
    );

    // Exactly one batch VCS call per project, regardless of how many file artifacts exist.
    assert_eq!(
        result.stats.vcs_batch_call_count, 1,
        "should make exactly one batch VCS call per project"
    );
}

#[test]
fn file_artifact_time_filter_stats_count_file() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    fs::write(dir.path().join("stale.log"), "log").unwrap();
    set_file_mtime(
        dir.path().join("stale.log"),
        FileTime::from_system_time(ten_days_ago()),
    )
    .unwrap();

    let patterns = get_artifact_patterns(false).unwrap();
    let options = ScanOptions {
        verbose: false,
        calculate_sizes: false,
    };
    let result = scan_single_path(
        dir.path().to_str().unwrap(),
        &patterns,
        &[],
        options,
        &older_than_five_days(),
    )
    .unwrap();

    assert_eq!(result.stats.total_found, 1);
    assert_eq!(result.stats.passed_time_filter, 1);
    assert_eq!(result.stats.excluded_by_time, 0);
}

#[test]
fn category2_directory_time_filter_stats_count_directory() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    fs::create_dir_all(dir.path().join("target")).unwrap();
    fs::write(dir.path().join("target/old.txt"), "old").unwrap();
    set_file_mtime(
        dir.path().join("target"),
        FileTime::from_system_time(ten_days_ago()),
    )
    .unwrap();

    let patterns = get_artifact_patterns(false).unwrap();
    let options = ScanOptions {
        verbose: false,
        calculate_sizes: false,
    };
    let result = scan_single_path(
        dir.path().to_str().unwrap(),
        &patterns,
        &[],
        options,
        &older_than_five_days(),
    )
    .unwrap();

    assert_eq!(result.stats.total_found, 1);
    assert_eq!(result.stats.passed_time_filter, 1);
    assert_eq!(result.stats.excluded_by_time, 0);
}

#[test]
fn category3_directory_time_filter_stats_count_files() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
    fs::create_dir_all(dir.path().join("dist")).unwrap();
    fs::write(dir.path().join("dist/old.txt"), "old").unwrap();
    fs::write(dir.path().join("dist/new.txt"), "new").unwrap();
    set_file_mtime(
        dir.path().join("dist/old.txt"),
        FileTime::from_system_time(ten_days_ago()),
    )
    .unwrap();
    // dist/new.txt keeps its current mtime (too recent)

    let patterns = get_artifact_patterns(false).unwrap();
    let options = ScanOptions {
        verbose: false,
        calculate_sizes: false,
    };
    let result = scan_single_path(
        dir.path().to_str().unwrap(),
        &patterns,
        &[],
        options,
        &older_than_five_days(),
    )
    .unwrap();

    // /dist is a Category 3 (non-recreatable) artifact directory. Its two
    // untracked files are the artifacts for time-filter accounting.
    assert_eq!(result.stats.total_found, 2);
    assert_eq!(result.stats.passed_time_filter, 1);
    assert_eq!(result.stats.excluded_by_time, 1);
}
