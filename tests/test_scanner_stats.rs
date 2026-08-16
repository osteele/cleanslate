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
