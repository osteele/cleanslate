use anyhow::{Context, Result};
use clap::Parser;
use cleanslate::{
    get_artifact_patterns, scan_single_path, truncate_name_with_suffix, ArtifactPattern,
    ProjectReport, ScanOptions, ScanResult, TimeFilter, TimeFilterStats,
};
use colored::Colorize;
use humansize::{format_size, BINARY};
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Find and optionally clean build artifacts and caches from various programming languages",
    long_about = None
)]
struct Args {
    /// Directories to scan (defaults to current directory)
    #[arg(default_values_t = vec![String::from(".")])]
    paths: Vec<String>,

    /// Delete the found artifacts
    #[arg(long, short)]
    delete: bool,

    /// Show detailed information about found artifacts
    #[arg(long, short)]
    verbose: bool,

    /// Show what would be deleted without actually deleting (implies --delete)
    #[arg(long)]
    dry_run: bool,

    /// Show detailed list format instead of table (table is default)
    #[arg(long, short)]
    list: bool,

    /// Aggressive mode: also remove small/trivial files like .DS_Store
    #[arg(long)]
    aggressive: bool,

    /// Exclude directories by name (can be specified multiple times)
    #[arg(long, short = 'x', value_name = "DIR")]
    exclude: Vec<String>,

    /// Only remove files modified more than the specified duration ago
    /// Supports: plain numbers (days), or with unit suffix: h (hours), d (days), w (weeks), m (months)
    /// Examples: 15, 15d, 2w, 3m, 48h
    #[arg(long, value_name = "DURATION")]
    older_than: Option<String>,

    /// Only remove files modified before a specific date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    modified_before: Option<String>,

    /// Calculate sizes of artifacts (slower, requires traversing directories)
    #[arg(long)]
    calculate_sizes: bool,
}

fn scan_for_artifacts(
    paths: &[String],
    options: ScanOptions,
    aggressive: bool,
    exclude: Vec<String>,
    older_than: Option<String>,
    modified_before: Option<String>,
) -> Result<()> {
    // Load patterns once (shared across all parallel scans)
    let patterns = get_artifact_patterns(aggressive).context("Failed to load artifact patterns")?;

    // Create time filter
    let time_filter = TimeFilter::from_args(older_than.as_deref(), modified_before.as_deref())?;

    // Canonicalize and deduplicate paths to prevent:
    // 1. Double-counting artifact sizes
    // 2. Race conditions during deletion
    // 3. Redundant scanning of overlapping paths
    let mut canonical_paths: HashSet<PathBuf> = HashSet::new();
    for path_str in paths {
        let path = PathBuf::from(path_str);
        match path.canonicalize() {
            Ok(canonical) => {
                canonical_paths.insert(canonical);
            }
            Err(e) => {
                eprintln!("Warning: Could not canonicalize path '{}': {}", path_str, e);
                // Still add the original path if canonicalization fails
                canonical_paths.insert(path);
            }
        }
    }

    let unique_paths: Vec<PathBuf> = canonical_paths.into_iter().collect();
    let unique_path_strings: Vec<String> = unique_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    // Scan paths in parallel
    let results: Vec<ScanResult> = unique_path_strings
        .par_iter()
        .map(|path| scan_single_path(path, &patterns, &exclude, options, &time_filter))
        .collect::<Result<Vec<_>>>()?;

    // Merge results from parallel scans
    let mut projects: HashMap<PathBuf, ProjectReport> = HashMap::new();
    let mut total_bytes: u64 = 0;
    let mut combined_stats = TimeFilterStats::default();

    for result in results {
        total_bytes += result.total_bytes;
        combined_stats.total_found += result.stats.total_found;
        combined_stats.passed_time_filter += result.stats.passed_time_filter;
        combined_stats.excluded_by_time += result.stats.excluded_by_time;
        for (project_path, project_report) in result.projects {
            projects
                .entry(project_path)
                .or_insert_with(|| ProjectReport {
                    artifacts: Vec::new(),
                })
                .artifacts
                .extend(project_report.artifacts);
        }
    }

    // Cleanup pass: Remove empty directories
    if options.delete && !options.dry_run {
        cleanup_empty_directories(&projects, options);
    }

    // Display results
    display_results(
        &projects,
        &unique_paths,
        &patterns,
        &time_filter,
        options,
        total_bytes,
        &combined_stats,
        paths,
        &older_than,
        &modified_before,
        aggressive,
        &exclude,
    );

    Ok(())
}

/// Remove empty directories after artifact deletion
fn cleanup_empty_directories(
    projects: &HashMap<PathBuf, ProjectReport>,
    options: ScanOptions,
) {
    // Collect all directories to check - both artifact dirs and parent dirs of removed files
    let mut dirs_to_check: HashSet<PathBuf> = HashSet::new();

    for project_report in projects.values() {
        for entry in &project_report.artifacts {
            if entry.removed {
                // If it's a directory artifact, add it
                if entry.path.is_dir()
                    || entry
                        .path
                        .symlink_metadata()
                        .map(|m| m.is_dir())
                        .unwrap_or(false)
                {
                    dirs_to_check.insert(entry.path.clone());
                    // Also add all parent directories up to the project root
                    let mut current = entry.path.as_path();
                    while let Some(parent) = current.parent() {
                        if dirs_to_check.insert(parent.to_path_buf()) {
                            current = parent;
                        } else {
                            break; // Already added, no need to go further
                        }
                    }
                } else {
                    // For files, add parent directories
                    if let Some(parent) = entry.path.parent() {
                        dirs_to_check.insert(parent.to_path_buf());
                        // Also add ancestor directories
                        let mut current = parent;
                        while let Some(parent) = current.parent() {
                            if dirs_to_check.insert(parent.to_path_buf()) {
                                current = parent;
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort directories by depth (deepest first) so we remove child dirs before parents
    let mut dirs_vec: Vec<PathBuf> = dirs_to_check.into_iter().collect();
    dirs_vec.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    // Try to remove empty directories
    // A directory is considered "empty" if it contains nothing OR only .DS_Store/Thumbs.db
    for dir in dirs_vec {
        // Skip if doesn't exist
        if !dir.exists() {
            continue;
        }

        // Check if directory is empty or only contains trivial files
        match fs::read_dir(&dir) {
            Ok(entries) => {
                // Collect all entries
                let remaining: Vec<_> = entries.filter_map(|e| e.ok()).collect();

                // Check if empty or only contains .DS_Store/Thumbs.db
                let is_effectively_empty = remaining.is_empty()
                    || remaining.iter().all(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .map(|name| matches!(name, ".DS_Store" | "Thumbs.db"))
                            .unwrap_or(false)
                    });

                if is_effectively_empty {
                    // Remove trivial files first if present
                    for entry in remaining {
                        if let Some(name) = entry.file_name().to_str() {
                            if matches!(name, ".DS_Store" | "Thumbs.db") {
                                let _ = fs::remove_file(entry.path());
                            }
                        }
                    }

                    // Directory is empty or now empty, try to remove it
                    match fs::remove_dir(&dir) {
                        Ok(_) => {
                            if options.verbose {
                                println!("Removed empty directory: {}", dir.display());
                            }
                        }
                        Err(err) => {
                            if options.verbose {
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

/// Display scan results in table or list format
#[allow(clippy::too_many_arguments)]
fn display_results(
    projects: &HashMap<PathBuf, ProjectReport>,
    unique_paths: &[PathBuf],
    patterns: &[ArtifactPattern],
    time_filter: &TimeFilter,
    options: ScanOptions,
    total_bytes: u64,
    combined_stats: &TimeFilterStats,
    paths: &[String],
    older_than: &Option<String>,
    modified_before: &Option<String>,
    aggressive: bool,
    exclude: &[String],
) {
    if projects.is_empty() {
        println!("No artifacts found.");
    } else if !options.list {
        display_table_format(
            projects,
            unique_paths,
            time_filter,
            options,
            paths,
            older_than,
            modified_before,
            aggressive,
            exclude,
        );
    } else {
        display_list_format(
            projects,
            unique_paths,
            patterns,
            time_filter,
            options,
            total_bytes,
            paths,
            older_than,
            modified_before,
            aggressive,
            exclude,
        );
    }

    // Show time filter statistics if active (for all output formats)
    if time_filter.is_active() && !projects.is_empty() {
        println!();
        println!(
            "Time Filter: {} of {} artifacts passed the filter ({} excluded)",
            combined_stats.passed_time_filter,
            combined_stats.total_found,
            combined_stats.excluded_by_time
        );
    }
}

/// Display results in table format (default)
#[allow(clippy::too_many_arguments)]
fn display_table_format(
    projects: &HashMap<PathBuf, ProjectReport>,
    unique_paths: &[PathBuf],
    time_filter: &TimeFilter,
    options: ScanOptions,
    paths: &[String],
    older_than: &Option<String>,
    modified_before: &Option<String>,
    aggressive: bool,
    exclude: &[String],
) {
    use terminal_size::{terminal_size, Width};

    let start_path = if unique_paths.len() == 1 {
        &unique_paths[0]
    } else {
        // For multiple paths, use current directory as base
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    // Collect and sort projects by path, filtering out empty projects
    let mut sorted_projects: Vec<_> = projects
        .iter()
        .filter(|(_, report)| {
            // If calculating sizes, filter by size. Otherwise, just check if there are artifacts.
            if options.calculate_sizes {
                let total: u64 = report.artifacts.iter().map(|a| a.size).sum();
                total > 0
            } else {
                !report.artifacts.is_empty()
            }
        })
        .collect();
    sorted_projects.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

    // If no projects to display, show a special message
    if sorted_projects.is_empty() {
        println!("\nNo artifacts found.");
        return;
    }

    // Count total artifacts across all projects
    let total_artifact_count: usize = sorted_projects
        .iter()
        .map(|(_, report)| report.artifacts.len())
        .sum();

    // Get terminal width (default to 120 if not available)
    let terminal_width = if let Some((Width(w), _)) = terminal_size() {
        w as usize
    } else {
        120
    };

    // Calculate max path width for alignment
    let max_path_width = sorted_projects
        .iter()
        .map(|(path, _)| {
            path.strip_prefix(start_path)
                .unwrap_or(path)
                .display()
                .to_string()
                .len()
        })
        .max()
        .unwrap_or(20)
        .min(40); // Cap path width at 40 chars

    // Fixed widths for size columns (only if calculate_sizes is enabled)
    let removable_width = if options.calculate_sizes { 12 } else { 0 };
    let too_recent_width = if options.calculate_sizes && time_filter.is_active() {
        12
    } else {
        0
    };

    // Calculate What column width
    let separator_width = if options.calculate_sizes {
        if time_filter.is_active() {
            6
        } else {
            4
        }
    } else {
        2 // Just "Path  What"
    };
    let what_width = terminal_width
        .saturating_sub(max_path_width)
        .saturating_sub(removable_width)
        .saturating_sub(too_recent_width)
        .saturating_sub(separator_width)
        .max(20);

    // Print header - hide size columns when not calculated
    if !options.calculate_sizes {
        // No size columns
        println!("{:<path_w$}  What", "Path", path_w = max_path_width);
    } else if time_filter.is_active() {
        println!(
            "{:<path_w$}  {:>rem_w$}  {:>rec_w$}  What",
            "Path",
            "Removable",
            "Too Recent",
            path_w = max_path_width,
            rem_w = removable_width,
            rec_w = too_recent_width
        );
    } else {
        println!(
            "{:<path_w$}  {:>rem_w$}  What",
            "Path",
            "Removable",
            path_w = max_path_width,
            rem_w = removable_width
        );
    }
    println!("{}", "─".repeat(terminal_width.min(120)));

    let mut total_removable: u64 = 0;
    let mut total_too_recent: u64 = 0;

    // Print each project
    for (project_dir, report) in &sorted_projects {
        let removable_size: u64 = report
            .artifacts
            .iter()
            .filter(|a| !a.time_filtered)
            .map(|a| a.size)
            .sum();
        let too_recent_size: u64 = report
            .artifacts
            .iter()
            .filter(|a| a.time_filtered)
            .map(|a| a.size)
            .sum();

        total_removable += removable_size;
        total_too_recent += too_recent_size;

        let relative_path = project_dir
            .strip_prefix(start_path)
            .unwrap_or(project_dir)
            .display()
            .to_string();
        let path_display = if relative_path.is_empty() {
            ".".to_string()
        } else {
            relative_path
        };

        // Collect artifact names sorted by size (largest first)
        let mut artifacts_with_size: Vec<(String, u64)> = report
            .artifacts
            .iter()
            .map(|a| {
                let name = a
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                (name, a.size)
            })
            .collect();
        artifacts_with_size.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by size desc

        // Build What column string with truncation
        let mut what_parts = Vec::new();
        let mut current_len = 0;
        let large_threshold = 50 * 1024 * 1024; // 50 MiB

        for (name, size) in &artifacts_with_size {
            let formatted = if *size > large_threshold {
                name.bold().to_string()
            } else {
                name.clone()
            };

            let add_len = if what_parts.is_empty() {
                formatted.len()
            } else {
                formatted.len() + 2 // ", " separator
            };

            if current_len + add_len > what_width {
                // Try to fit a truncated version of the current artifact
                let separator_len = if what_parts.is_empty() { 0 } else { 2 }; // ", "
                let remaining_width = what_width.saturating_sub(current_len + separator_len);

                if remaining_width >= 6 {
                    // Minimum for showing something useful (e.g., "foo...")
                    let truncated = truncate_name_with_suffix(name, remaining_width);
                    let truncated_formatted = if *size > large_threshold {
                        truncated.bold().to_string()
                    } else {
                        truncated
                    };
                    what_parts.push(truncated_formatted);
                } else if !what_parts.is_empty() {
                    // Not enough room for partial name, just add "..." if we have previous items
                    what_parts.push("...".to_string());
                }
                break;
            }

            what_parts.push(formatted);
            current_len += add_len;
        }

        let what_display = what_parts.join(", ");

        // Print row based on whether sizes are calculated
        if !options.calculate_sizes {
            // No size columns - just path and what
            println!(
                "{:<path_w$}  {}",
                path_display,
                what_display,
                path_w = max_path_width
            );
        } else {
            // Apply styling based on thresholds
            let removable_display = if removable_size > 100 * 1024 * 1024 {
                format_size(removable_size, BINARY).bold().red()
            } else {
                format_size(removable_size, BINARY).normal()
            };

            // Style path based on removable size
            let path_styled = if removable_size > 100 * 1024 * 1024 {
                path_display.bold().yellow()
            } else {
                path_display.normal()
            };

            if time_filter.is_active() {
                println!(
                    "{:<path_w$}  {:>rem_w$}  {:>rec_w$}  {}",
                    path_styled,
                    removable_display,
                    format_size(too_recent_size, BINARY),
                    what_display,
                    path_w = max_path_width,
                    rem_w = removable_width,
                    rec_w = too_recent_width
                );
            } else {
                println!(
                    "{:<path_w$}  {:>rem_w$}  {}",
                    path_styled,
                    removable_display,
                    what_display,
                    path_w = max_path_width,
                    rem_w = removable_width
                );
            }
        }
    }

    println!("{}", "─".repeat(terminal_width.min(120)));

    // Print total row
    if !options.calculate_sizes {
        // Show count of projects and artifacts instead of sizes
        println!(
            "\nFound {} artifact(s) across {} project(s). Use --calculate-sizes to see sizes.",
            total_artifact_count,
            sorted_projects.len()
        );
    } else if time_filter.is_active() {
        println!(
            "{:<path_w$}  {:>rem_w$}  {:>rec_w$}",
            "Total",
            format_size(total_removable, BINARY),
            format_size(total_too_recent, BINARY),
            path_w = max_path_width,
            rem_w = removable_width,
            rec_w = too_recent_width
        );
    } else {
        println!(
            "{:<path_w$}  {:>rem_w$}",
            "Total",
            format_size(total_removable, BINARY),
            path_w = max_path_width,
            rem_w = removable_width
        );
    }

    // Show deletion summary for table format
    if options.delete && !options.dry_run {
        let removed_bytes: u64 = projects
            .values()
            .flat_map(|r| &r.artifacts)
            .filter(|a| a.removed)
            .map(|a| a.size)
            .sum();
        println!(
            "\nTotal Size Removed: {}",
            format_size(removed_bytes, BINARY).bold().red()
        );
    } else if options.dry_run {
        println!("\nDry run mode: No files were deleted.");
    } else if !options.delete && total_removable > 0 {
        print_delete_command(paths, older_than, modified_before, aggressive, exclude);
    }

    println!("\nRun with --list to see detailed breakdown by project");
}

/// Display results in list format
#[allow(clippy::too_many_arguments)]
fn display_list_format(
    projects: &HashMap<PathBuf, ProjectReport>,
    unique_paths: &[PathBuf],
    patterns: &[ArtifactPattern],
    time_filter: &TimeFilter,
    options: ScanOptions,
    total_bytes: u64,
    paths: &[String],
    older_than: &Option<String>,
    modified_before: &Option<String>,
    aggressive: bool,
    exclude: &[String],
) {
    let start_path = if unique_paths.len() == 1 {
        &unique_paths[0]
    } else {
        // For multiple paths, use current directory as base
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    // Sort projects alphabetically by path
    let mut sorted_projects: Vec<_> = projects.iter().collect();
    sorted_projects.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

    for (project_dir, report) in sorted_projects {
        let removable_size: u64 = report
            .artifacts
            .iter()
            .filter(|a| !a.time_filtered)
            .map(|a| a.size)
            .sum();
        let too_recent_size: u64 = report
            .artifacts
            .iter()
            .filter(|a| a.time_filtered)
            .map(|a| a.size)
            .sum();
        let total_project_size = removable_size + too_recent_size;

        // Skip empty projects - check artifact count when sizes not calculated
        let has_artifacts = if options.calculate_sizes {
            total_project_size > 0
        } else {
            !report.artifacts.is_empty()
        };
        if !has_artifacts {
            continue;
        }

        // Get relative path from search root
        let relative_path = project_dir
            .strip_prefix(start_path)
            .unwrap_or(project_dir)
            .display()
            .to_string();
        let path_display = if relative_path.is_empty() {
            ".".to_string()
        } else {
            relative_path
        };

        println!("{}", path_display.bold());

        // Aggregate by language and collect artifact names
        let mut language_summary: HashMap<String, (u64, Vec<String>)> = HashMap::new();

        for artifact in &report.artifacts {
            let path = &artifact.path;
            let path_str = path.to_string_lossy();
            let filename = path
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default()
                .to_string();

            // Find the matching pattern to get the language
            if let Some(matching_pattern) = patterns
                .iter()
                .find(|p| p.pattern == filename || path_str.contains(&p.pattern))
            {
                let entry = language_summary
                    .entry(matching_pattern.language_name.clone())
                    .or_insert((0, Vec::new()));
                entry.0 += artifact.size;
                if !entry.1.contains(&filename) {
                    entry.1.push(filename);
                }
            }
        }

        // Sort languages alphabetically
        let mut languages: Vec<_> = language_summary.into_iter().collect();
        languages.sort_by(|a, b| a.0.cmp(&b.0));

        for (language, (size, artifacts)) in languages {
            let artifacts_str = artifacts.join(", ");
            println!(
                "  - {}: {} ({})",
                language,
                format_size(size, BINARY),
                artifacts_str
            );
        }

        if time_filter.is_active() && too_recent_size > 0 {
            println!(
                "  {} (Removable: {}, Too Recent: {})",
                format!("Total: {}", format_size(total_project_size, BINARY)).green(),
                format_size(removable_size, BINARY),
                format_size(too_recent_size, BINARY)
            );
        } else {
            println!(
                "  {}",
                format!("Total: {}", format_size(total_project_size, BINARY)).green()
            );
        }
        println!(); // Add a blank line between projects
    }

    println!("========================================");
    println!(
        "Total Size Found: {}",
        format_size(total_bytes, BINARY).bold()
    );
    if options.delete && !options.dry_run {
        let removed_bytes: u64 = projects
            .values()
            .flat_map(|r| &r.artifacts)
            .filter(|a| a.removed)
            .map(|a| a.size)
            .sum();
        println!(
            "Total Size Removed: {}",
            format_size(removed_bytes, BINARY).bold().red()
        );
    } else if options.dry_run {
        println!("Dry run mode: No files were deleted.");
    } else if !options.delete && total_bytes > 0 {
        print_delete_command(paths, older_than, modified_before, aggressive, exclude);
    }
}

/// Print the command to delete artifacts
fn print_delete_command(
    paths: &[String],
    older_than: &Option<String>,
    modified_before: &Option<String>,
    aggressive: bool,
    exclude: &[String],
) {
    let mut cmd = String::from("cleanslate --delete");
    if let Some(days) = older_than {
        cmd.push_str(&format!(" --older-than {}", days));
    }
    if let Some(ref date) = modified_before {
        cmd.push_str(&format!(" --modified-before {}", date));
    }
    if aggressive {
        cmd.push_str(" --aggressive");
    }
    for ex in exclude {
        cmd.push_str(&format!(" --exclude {}", ex));
    }
    if !paths.is_empty() && paths[0] != "." {
        for path in paths {
            cmd.push_str(&format!(" {}", path));
        }
    }
    println!("\nTo delete: {}", cmd);
}

fn main() -> Result<()> {
    let args = Args::parse();

    let options = ScanOptions {
        delete: args.delete,
        verbose: args.verbose,
        dry_run: args.dry_run,
        list: args.list,
        calculate_sizes: args.calculate_sizes,
    };

    scan_for_artifacts(
        &args.paths,
        options,
        args.aggressive,
        args.exclude,
        args.older_than,
        args.modified_before,
    )?;

    Ok(())
}
