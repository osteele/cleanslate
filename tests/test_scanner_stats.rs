use cleanslate::{get_artifact_patterns, scan_single_path, ScanOptions, TimeFilter};
use filetime::{set_file_mtime, FileTime};
use std::fs;
use std::time::{Duration, SystemTime};
use tempfile::tempdir;

fn scan_options(calculate_sizes: bool) -> ScanOptions {
    ScanOptions {
        verbose: false,
        calculate_sizes,
        color: false,
    }
}

fn scan(
    dir: &std::path::Path,
    exclude: &[String],
    options: ScanOptions,
    filter: &TimeFilter,
) -> cleanslate::ScanResult {
    let patterns = get_artifact_patterns(false).unwrap();
    scan_single_path(dir.to_str().unwrap(), &patterns, exclude, options, filter).unwrap()
}

fn all_artifacts(result: &cleanslate::ScanResult) -> Vec<&cleanslate::ArtifactEntry> {
    result
        .projects
        .values()
        .flat_map(|r| &r.artifacts)
        .collect()
}

/// Sizes must be computed exactly: directory sizes sum their contained files,
/// skip VCS-internal subdirectories, and the grand total adds up across
/// category-2 directories, category-3 directories, and file artifacts.
#[test]
fn sizes_are_computed_exactly_for_mixed_tree() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"t\"").unwrap();

    // Category 2: target with two files and a nested subdirectory, so the
    // recursive size accumulation across subdirectories is exercised. (A
    // .git-named subdir would trip the nested-repository protection and skip
    // the artifact entirely, so VCS-internal names cannot appear here.)
    fs::create_dir_all(dir.path().join("target/sub")).unwrap();
    fs::write(dir.path().join("target/a.txt"), "a".repeat(10)).unwrap();
    fs::write(dir.path().join("target/b.txt"), "b".repeat(20)).unwrap();
    fs::write(dir.path().join("target/sub/c.txt"), "c".repeat(8)).unwrap();

    // Category 3: dist with one untracked file.
    fs::create_dir_all(dir.path().join("dist")).unwrap();
    fs::write(dir.path().join("dist/old.txt"), "o".repeat(5)).unwrap();

    // File artifact.
    fs::write(dir.path().join("stale.log"), "s".repeat(7)).unwrap();

    let result = scan(
        dir.path(),
        &[],
        scan_options(true),
        &TimeFilter::from_args(None, None).unwrap(),
    );

    let root = dir.path().canonicalize().unwrap();
    let artifacts = all_artifacts(&result);
    assert_eq!(artifacts.len(), 3, "target, dist, stale.log");

    let by_name = |name: &str| {
        artifacts
            .iter()
            .find(|a| a.path.file_name().unwrap() == name)
            .unwrap_or_else(|| panic!("missing artifact {}", name))
    };
    assert_eq!(
        by_name("target").size,
        38,
        "target sums nested subdirectories"
    );
    assert_eq!(by_name("dist").size, 5);
    assert_eq!(by_name("stale.log").size, 7);
    assert_eq!(by_name("dist").files, vec![root.join("dist/old.txt")]);

    assert_eq!(result.total_bytes, 10 + 20 + 8 + 5 + 7);
}

/// Excluding a directory name must actually suppress that artifact, not just
/// leave the others findable.
#[test]
fn excluded_directory_artifacts_are_not_reported() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"t\"").unwrap();
    fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    fs::write(dir.path().join("node_modules/x.js"), "x").unwrap();
    fs::create_dir_all(dir.path().join("target")).unwrap();
    fs::write(dir.path().join("target/a.txt"), "a").unwrap();

    let result = scan(
        dir.path(),
        &["node_modules".to_string()],
        scan_options(false),
        &TimeFilter::from_args(None, None).unwrap(),
    );

    let names: Vec<_> = all_artifacts(&result)
        .iter()
        .map(|a| a.path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(names.contains(&"target".to_string()), "got: {:?}", names);
    assert!(
        !names.iter().any(|n| n == "node_modules"),
        "excluded artifact must not be reported, got: {:?}",
        names
    );
}

/// In a project whose VCS call fails (broken .git), every artifact — category-2
/// directory, category-3 directory, and file — is kept and counted in
/// vcs_check_failures.
#[test]
fn vcs_failure_counts_directory_and_file_artifacts() {
    let dir = tempdir().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap(); // not a real repo: git ls-files fails
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"t\"").unwrap();
    fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    fs::write(dir.path().join("node_modules/x.js"), "x").unwrap();
    fs::create_dir_all(dir.path().join("dist")).unwrap();
    fs::write(dir.path().join("dist/y.txt"), "y").unwrap();
    fs::write(dir.path().join("stale.log"), "s").unwrap();

    let result = scan(
        dir.path(),
        &[],
        scan_options(false),
        &TimeFilter::from_args(None, None).unwrap(),
    );

    assert_eq!(result.stats.vcs_check_failures, 3);
    assert!(
        all_artifacts(&result).is_empty(),
        "fail-closed: nothing may be reported when tracking is unknown"
    );
}

/// A directory inside an artifact that cannot be read makes the nested-VCS
/// inspection fail; the artifact is kept and the failure is counted.
#[cfg(unix)]
#[test]
fn unreadable_subdirectory_inside_artifact_is_counted_as_vcs_failure() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"t\"").unwrap();
    let locked = dir.path().join("node_modules/locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("x.js"), "x").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    let result = scan(
        dir.path(),
        &[],
        scan_options(false),
        &TimeFilter::from_args(None, None).unwrap(),
    );

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(result.stats.vcs_check_failures, 1);
    assert!(all_artifacts(&result).is_empty());
}

/// Time filtering must mark entries (time_filtered flag), count stats for both
/// file artifacts and recreatable directories, and exclude filtered sizes from
/// the total.
#[test]
fn time_filter_marks_entries_and_counts_stats() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"t\"").unwrap();

    fs::write(dir.path().join("stale.log"), "s".repeat(7)).unwrap();
    set_file_mtime(
        dir.path().join("stale.log"),
        FileTime::from_system_time(ten_days_ago()),
    )
    .unwrap();
    fs::write(dir.path().join("fresh.log"), "f".repeat(5)).unwrap();

    let old_target = dir.path().join("target");
    fs::create_dir_all(&old_target).unwrap();
    fs::write(old_target.join("a.txt"), "a").unwrap();
    set_file_mtime(&old_target, FileTime::from_system_time(ten_days_ago())).unwrap();

    let result = scan(dir.path(), &[], scan_options(true), &older_than_five_days());

    let root = dir.path().canonicalize().unwrap();
    let artifacts = all_artifacts(&result);
    assert_eq!(artifacts.len(), 3, "stale.log, fresh.log, target");

    let stale = artifacts
        .iter()
        .find(|a| a.path == root.join("stale.log"))
        .unwrap();
    assert!(!stale.time_filtered, "old file passes the filter");
    let fresh = artifacts
        .iter()
        .find(|a| a.path == root.join("fresh.log"))
        .unwrap();
    assert!(
        fresh.time_filtered,
        "recent file must be marked time_filtered"
    );
    let target = artifacts
        .iter()
        .find(|a| a.path == root.join("target"))
        .unwrap();
    assert!(!target.time_filtered);

    assert_eq!(result.stats.total_found, 3);
    assert_eq!(result.stats.passed_time_filter, 2);
    assert_eq!(result.stats.excluded_by_time, 1);
    assert_eq!(result.total_bytes, 7 + 1, "only unfiltered sizes count");
}

/// A recreatable directory that fails the time filter is counted in
/// excluded_by_time and contributes no bytes.
#[test]
fn time_filtered_category2_directory_is_counted_and_excluded() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"t\"").unwrap();
    let target = dir.path().join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("a.txt"), "a".repeat(11)).unwrap();
    set_file_mtime(&target, FileTime::from_system_time(ten_days_ago())).unwrap();

    // Filter that the old directory fails: older than 20 days.
    let result = scan(
        dir.path(),
        &[],
        scan_options(true),
        &TimeFilter::from_args(Some("20d"), None).unwrap(),
    );

    assert_eq!(result.stats.total_found, 1);
    assert_eq!(result.stats.passed_time_filter, 0);
    assert_eq!(result.stats.excluded_by_time, 1);
    assert_eq!(result.total_bytes, 0);
    assert!(all_artifacts(&result)[0].time_filtered);
}

/// Discovery must attribute artifacts to real nested projects (and only to
/// them): a project inside the scan root becomes THE project, and a deeper
/// nested project is not discovered separately because discovery stops
/// descending into discovered roots.
#[test]
fn discovery_attributes_artifacts_to_nested_project_only() {
    let dir = tempdir().unwrap();
    let proj = dir.path().join("proj");
    fs::create_dir_all(proj.join("__pycache__")).unwrap();
    fs::create_dir_all(proj.join("sub/inner/__pycache__")).unwrap();
    fs::write(proj.join("Cargo.toml"), "[package]\nname = \"p\"").unwrap();
    fs::write(proj.join("__pycache__/x.pyc"), "x").unwrap();
    fs::write(proj.join("sub/inner/Cargo.toml"), "[package]\nname = \"i\"").unwrap();
    fs::write(proj.join("sub/inner/__pycache__/y.pyc"), "y").unwrap();

    let result = scan(
        dir.path(),
        &[],
        scan_options(false),
        &TimeFilter::from_args(None, None).unwrap(),
    );

    let canonical_proj = proj.canonicalize().unwrap();
    assert_eq!(
        result.projects.len(),
        1,
        "only the outer project is discovered, got: {:?}",
        result.projects.keys()
    );
    assert!(result.projects.contains_key(&canonical_proj));
    let mut artifact_paths: Vec<_> = result.projects[&canonical_proj]
        .artifacts
        .iter()
        .map(|a| a.path.clone())
        .collect();
    artifact_paths.sort();
    assert_eq!(
        artifact_paths,
        vec![
            canonical_proj.join("__pycache__"),
            canonical_proj.join("sub/inner/__pycache__"),
        ]
    );
}

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
        color: false,
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

/// Regression test: `git ls-files` C-quotes tracked paths containing `"` (and
/// non-ASCII under the default core.quotePath). Those tracked files must be
/// recognized as tracked, not misclassified as untracked and offered for removal.
#[test]
fn git_tracked_files_with_quoted_names_are_kept() {
    use std::process::Command;

    let dir = tempdir().unwrap();

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

    // Tracked files whose `git ls-files` output is quoted. `"` is not a legal
    // filename character on Windows, so the quote-path half is unix-only; the
    // non-ASCII half (quoted under the default core.quotePath) runs everywhere.
    let unicode_name = "café.aux";
    fs::write(dir.path().join(unicode_name), "tracked").unwrap();
    #[cfg(not(windows))]
    let quoted_name = "quote\"name.aux";
    #[cfg(not(windows))]
    fs::write(dir.path().join(quoted_name), "tracked").unwrap();
    let mut add = Command::new("git");
    add.arg("add").arg("--").arg(unicode_name);
    #[cfg(not(windows))]
    add.arg(quoted_name);
    add.current_dir(dir.path())
        .output()
        .expect("git add failed");
    Command::new("git")
        .args(["commit", "-m", "track quoted names"])
        .current_dir(dir.path())
        .output()
        .expect("git commit failed");

    // An untracked artifact of the same kind should still be reported.
    fs::write(dir.path().join("untracked.aux"), "untracked").unwrap();

    let patterns = get_artifact_patterns(false).unwrap();
    let options = ScanOptions {
        verbose: false,
        calculate_sizes: false,
        color: false,
    };
    let result = scan_single_path(
        dir.path().to_str().unwrap(),
        &patterns,
        &[],
        options,
        &TimeFilter::from_args(None, None).unwrap(),
    )
    .unwrap();

    let reported_names: Vec<_> = result
        .projects
        .values()
        .flat_map(|r| &r.artifacts)
        .filter_map(|a| a.path.file_name().map(|n| n.to_string_lossy().to_string()))
        .collect();
    assert!(
        !reported_names
            .iter()
            .any(|n| n.contains("name.aux") && n != "untracked.aux"),
        "tracked quoted-path files must not be reported for removal, got: {:?}",
        reported_names
    );
    assert!(
        !reported_names
            .iter()
            .any(|n| n.contains("name.aux") && n != "untracked.aux"),
        "tracked quoted-path files must not be reported for removal, got: {:?}",
        reported_names
    );
    assert!(
        !reported_names.iter().any(|n| n == "café.aux"),
        "tracked non-ASCII (quotePath-quoted) file must not be reported, got: {:?}",
        reported_names
    );
}

/// Regression test: a project indicator inside an artifact directory (every
/// installed npm package has a package.json) must not turn the package into a
/// discovered project, which would suppress the fallback scan and leave the
/// enclosing artifact directory itself unreported.
#[test]
fn artifact_directory_with_nested_project_is_reported_as_one_unit() {
    let dir = tempdir().unwrap();
    // No project marker at the scan root: only node_modules/inner has one.
    let inner = dir.path().join("node_modules/inner");
    fs::create_dir_all(inner.join("dist")).unwrap();
    fs::write(inner.join("package.json"), "{}").unwrap();
    fs::write(inner.join("dist/stale.txt"), "stale").unwrap();

    let patterns = get_artifact_patterns(false).unwrap();
    let options = ScanOptions {
        verbose: false,
        calculate_sizes: false,
        color: false,
    };
    let result = scan_single_path(
        dir.path().to_str().unwrap(),
        &patterns,
        &[],
        options,
        &TimeFilter::from_args(None, None).unwrap(),
    )
    .unwrap();

    // Exactly one project: the fallback root. node_modules is the artifact.
    assert_eq!(
        result.projects.len(),
        1,
        "expected only the fallback scan root as project, got: {:?}",
        result.projects.keys()
    );
    let artifacts: Vec<_> = result
        .projects
        .values()
        .flat_map(|r| &r.artifacts)
        .map(|a| a.path.clone())
        .collect();
    assert_eq!(
        artifacts,
        vec![dir.path().canonicalize().unwrap().join("node_modules")],
        "node_modules itself must be reported as the artifact, not its contents"
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
        color: false,
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
        color: false,
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
        color: false,
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
