use anyhow::{Context, Result};
use clap::Parser;
use cleanslate::{
    execute_plan, format_age, get_artifact_patterns, scan_single_path, truncate_name_with_suffix,
    ExecutionSummary, ProjectReport, ScanOptions, ScanResult, ScanStats, TimeFilter,
};
use colored::Colorize;
use humansize::{format_size, BINARY};
use inquire::{MultiSelect, Select};
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    io::IsTerminal,
    path::PathBuf,
    time::SystemTime,
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

    /// Skip the interactive confirmation prompt and delete all matched artifacts
    #[arg(long, short, requires = "delete")]
    yes: bool,

    /// Show detailed information about found artifacts
    #[arg(long, short)]
    verbose: bool,

    /// Preview what would be deleted without deleting (cannot be combined with --delete)
    #[arg(long, conflicts_with = "delete")]
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

    /// Skip artifact size calculation for a faster scan
    #[arg(long)]
    no_sizes: bool,

    /// Deprecated: sizes are calculated by default; this flag is ignored
    #[arg(long, hide = true)]
    calculate_sizes: bool,
}

fn remove_overlapping_paths(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort_by_key(|path| path.components().count());
    let mut unique_paths = Vec::new();
    for path in paths {
        if !unique_paths
            .iter()
            .any(|ancestor: &PathBuf| path.starts_with(ancestor))
        {
            unique_paths.push(path);
        }
    }
    unique_paths
}

fn scan_for_artifacts(
    paths: &[String],
    options: ScanOptions,
    aggressive: bool,
    exclude: Vec<String>,
    older_than: Option<String>,
    modified_before: Option<String>,
) -> Result<(ScanResult, Vec<PathBuf>)> {
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

    let unique_paths = remove_overlapping_paths(canonical_paths.into_iter().collect());
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
    let mut combined_stats = ScanStats::default();

    for result in results {
        total_bytes += result.total_bytes;
        combined_stats.total_found += result.stats.total_found;
        combined_stats.passed_time_filter += result.stats.passed_time_filter;
        combined_stats.excluded_by_time += result.stats.excluded_by_time;
        combined_stats.vcs_check_failures += result.stats.vcs_check_failures;
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

    Ok((
        ScanResult {
            projects,
            total_bytes,
            stats: combined_stats,
        },
        unique_paths,
    ))
}

/// Everything the report display needs, bundled to keep display signatures small
struct Report<'a> {
    projects: &'a HashMap<PathBuf, ProjectReport>,
    unique_paths: &'a [PathBuf],
    time_filter: &'a TimeFilter,
    total_bytes: u64,
    stats: &'a ScanStats,
    calculate_sizes: bool,
    now: SystemTime,
}

/// Age of the project's most recently modified artifact, formatted for display.
/// The freshest artifact is the conservative signal for whether a project is still in use.
fn project_age_display(project_report: &ProjectReport, now: SystemTime) -> String {
    project_report
        .artifacts
        .iter()
        .filter_map(|a| a.modified)
        .max()
        .map(|modified| format_age(modified, now))
        .unwrap_or_else(|| "-".to_string())
}

/// Warn when artifacts were kept because their VCS status could not be determined
fn print_vcs_failure_notice(stats: &ScanStats, verbose: bool) {
    if stats.vcs_check_failures > 0 && !verbose {
        eprintln!(
            "{} artifact(s) skipped because their version-control status could not be determined; rerun with --verbose for details.",
            stats.vcs_check_failures
        );
    }
}

/// CLI arguments needed to reproduce this scan as a deletion command
struct DeleteCommand<'a> {
    paths: &'a [String],
    older_than: &'a Option<String>,
    modified_before: &'a Option<String>,
    aggressive: bool,
    exclude: &'a [String],
}

/// Display scan results in table or list format
fn display_results(report: &Report, list: bool) {
    println!();
    if report.projects.is_empty() {
        println!("No artifacts found.");
    } else if !list {
        display_table_format(report);
    } else {
        display_list_format(report);
    }

    // Show time filter statistics if active (for all output formats)
    if report.time_filter.is_active() && !report.projects.is_empty() {
        println!();
        println!(
            "Time Filter: {} of {} artifacts passed the filter ({} excluded)",
            report.stats.passed_time_filter,
            report.stats.total_found,
            report.stats.excluded_by_time
        );
    }
}

/// Display results in table format (default)
fn display_table_format(report: &Report) {
    use terminal_size::{terminal_size, Width};

    let projects = report.projects;
    let time_filter = report.time_filter;

    let start_path = if report.unique_paths.len() == 1 {
        &report.unique_paths[0]
    } else {
        // For multiple paths, use current directory as base
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    // Collect and sort projects by path, filtering out empty projects
    let mut sorted_projects: Vec<_> = projects
        .iter()
        .filter(|(_, project_report)| {
            // If calculating sizes, filter by size. Otherwise, just check if there are artifacts.
            if report.calculate_sizes {
                let total: u64 = project_report.artifacts.iter().map(|a| a.size).sum();
                total > 0
            } else {
                !project_report.artifacts.is_empty()
            }
        })
        .collect();
    sorted_projects.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

    // If no projects to display, show a special message
    if sorted_projects.is_empty() {
        println!("No artifacts found.");
        return;
    }

    // Count total artifacts across all projects
    let total_artifact_count: usize = sorted_projects
        .iter()
        .map(|(_, project_report)| project_report.artifacts.len())
        .sum();

    // Get terminal width (default to 120 if not available)
    let terminal_width = if let Some((Width(w), _)) = terminal_size() {
        w as usize
    } else {
        120
    };

    // Calculate max path width for alignment. The "Path" header and the "Total"
    // label share this column, so the width must accommodate them too.
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
        .min(40) // Cap path width at 40 chars
        .max("Total".len());

    // Fixed widths for the size columns (only if sizes are shown) and the Age column
    let removable_width = if report.calculate_sizes { 12 } else { 0 };
    let too_recent_width = if report.calculate_sizes && time_filter.is_active() {
        12
    } else {
        0
    };
    let age_width = 5;

    // Calculate What column width
    let separator_width = if report.calculate_sizes {
        if time_filter.is_active() {
            8
        } else {
            6
        }
    } else {
        4 // "Path  Age  What"
    };
    let what_width = terminal_width
        .saturating_sub(max_path_width)
        .saturating_sub(removable_width)
        .saturating_sub(too_recent_width)
        .saturating_sub(age_width)
        .saturating_sub(separator_width)
        .max(20);

    // Print header - hide size columns when sizes were not calculated
    if !report.calculate_sizes {
        println!(
            "{:<path_w$}  {:>age_w$}  What",
            "Path",
            "Age",
            path_w = max_path_width,
            age_w = age_width
        );
    } else if time_filter.is_active() {
        println!(
            "{:<path_w$}  {:>rem_w$}  {:>rec_w$}  {:>age_w$}  What",
            "Path",
            "Removable",
            "Too Recent",
            "Age",
            path_w = max_path_width,
            rem_w = removable_width,
            rec_w = too_recent_width,
            age_w = age_width
        );
    } else {
        println!(
            "{:<path_w$}  {:>rem_w$}  {:>age_w$}  What",
            "Path",
            "Removable",
            "Age",
            path_w = max_path_width,
            rem_w = removable_width,
            age_w = age_width
        );
    }
    println!("{}", "─".repeat(terminal_width.min(120)));

    let mut total_removable: u64 = 0;
    let mut total_too_recent: u64 = 0;

    // Print each project
    for (project_dir, project_report) in &sorted_projects {
        let removable_size: u64 = project_report
            .artifacts
            .iter()
            .filter(|a| !a.time_filtered)
            .map(|a| a.size)
            .sum();
        let too_recent_size: u64 = project_report
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
        let mut artifacts_with_size: Vec<(String, u64)> = project_report
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
        let age_display = project_age_display(project_report, report.now);

        // Print row based on whether sizes were calculated
        if !report.calculate_sizes {
            // No size columns - just path, age, and what
            println!(
                "{:<path_w$}  {:>age_w$}  {}",
                path_display,
                age_display,
                what_display,
                path_w = max_path_width,
                age_w = age_width
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
                    "{:<path_w$}  {:>rem_w$}  {:>rec_w$}  {:>age_w$}  {}",
                    path_styled,
                    removable_display,
                    format_size(too_recent_size, BINARY),
                    age_display,
                    what_display,
                    path_w = max_path_width,
                    rem_w = removable_width,
                    rec_w = too_recent_width,
                    age_w = age_width
                );
            } else {
                println!(
                    "{:<path_w$}  {:>rem_w$}  {:>age_w$}  {}",
                    path_styled,
                    removable_display,
                    age_display,
                    what_display,
                    path_w = max_path_width,
                    rem_w = removable_width,
                    age_w = age_width
                );
            }
        }
    }

    println!("{}", "─".repeat(terminal_width.min(120)));

    // Print total row
    if !report.calculate_sizes {
        // Show count of projects and artifacts instead of sizes
        println!(
            "\nFound {} artifact(s) across {} project(s).",
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

    println!("\nRun with --list to see detailed breakdown by project");
}

/// Display results in list format
fn display_list_format(report: &Report) {
    let start_path = if report.unique_paths.len() == 1 {
        &report.unique_paths[0]
    } else {
        // For multiple paths, use current directory as base
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    // Sort projects alphabetically by path
    let mut sorted_projects: Vec<_> = report.projects.iter().collect();
    sorted_projects.sort_by_key(|(path, _)| path.to_string_lossy().to_string());

    for (project_dir, project_report) in sorted_projects {
        let removable_size: u64 = project_report
            .artifacts
            .iter()
            .filter(|a| !a.time_filtered)
            .map(|a| a.size)
            .sum();
        let too_recent_size: u64 = project_report
            .artifacts
            .iter()
            .filter(|a| a.time_filtered)
            .map(|a| a.size)
            .sum();
        let total_project_size = removable_size + too_recent_size;

        // Skip empty projects - check artifact count when sizes not calculated
        let has_artifacts = if report.calculate_sizes {
            total_project_size > 0
        } else {
            !project_report.artifacts.is_empty()
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

        // Aggregate by the language recorded at match time and collect artifact names
        let mut language_summary: HashMap<String, (u64, Vec<String>)> = HashMap::new();

        for artifact in &project_report.artifacts {
            let filename = artifact
                .path
                .file_name()
                .map(|f| f.to_string_lossy())
                .unwrap_or_default()
                .to_string();

            let entry = language_summary
                .entry(artifact.language_name.clone())
                .or_insert((0, Vec::new()));
            entry.0 += artifact.size;
            if !entry.1.contains(&filename) {
                entry.1.push(filename);
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

        if report.time_filter.is_active() && too_recent_size > 0 {
            println!(
                "  {} (Removable: {}, Too Recent: {}, Age: {})",
                format!("Total: {}", format_size(total_project_size, BINARY)).green(),
                format_size(removable_size, BINARY),
                format_size(too_recent_size, BINARY),
                project_age_display(project_report, report.now)
            );
        } else {
            println!(
                "  {} (Age: {})",
                format!("Total: {}", format_size(total_project_size, BINARY)).green(),
                project_age_display(project_report, report.now)
            );
        }
        println!(); // Add a blank line between projects
    }

    println!("========================================");
    println!(
        "Total Size Found: {}",
        format_size(report.total_bytes, BINARY).bold()
    );
}

/// Print the command to delete artifacts
fn print_delete_command(cmd: &DeleteCommand) {
    let mut command = String::from("cleanslate --delete");
    if let Some(days) = cmd.older_than {
        command.push_str(&format!(" --older-than {}", days));
    }
    if let Some(ref date) = cmd.modified_before {
        command.push_str(&format!(" --modified-before {}", date));
    }
    if cmd.aggressive {
        command.push_str(" --aggressive");
    }
    for ex in cmd.exclude {
        command.push_str(&format!(" --exclude {}", ex));
    }
    if !cmd.paths.is_empty() && cmd.paths[0] != "." {
        for path in cmd.paths {
            command.push_str(&format!(" {}", path));
        }
    }
    println!("\nTo delete: {}", command);
}

/// Whether the scan found any artifact that a deletion run would act on
fn has_removable_artifacts(projects: &HashMap<PathBuf, ProjectReport>) -> bool {
    projects
        .values()
        .any(|report| report.artifacts.iter().any(|a| !a.time_filtered))
}

/// Decide whether a plain scan should offer to delete interactively.
fn should_offer_deletion(
    delete: bool,
    dry_run: bool,
    stdout_tty: bool,
    stdin_tty: bool,
    stderr_tty: bool,
    has_removable: bool,
) -> bool {
    !delete && !dry_run && stdout_tty && stdin_tty && stderr_tty && has_removable
}

/// Decide whether a `--delete` run without `--yes` must be refused because there
/// is no terminal to prompt on.
fn should_refuse_non_interactive_delete(
    delete: bool,
    yes: bool,
    stdin_tty: bool,
    stderr_tty: bool,
) -> bool {
    delete && !yes && (!stdin_tty || !stderr_tty)
}

/// Prompt the user to select which projects to clean. Returns None if the prompt is canceled.
fn select_projects_interactively(
    projects: &HashMap<PathBuf, ProjectReport>,
    unique_paths: &[PathBuf],
    calculate_sizes: bool,
) -> Result<Option<HashSet<PathBuf>>> {
    // Build the list of projects shown in the multi-select prompt.
    let start_path = if unique_paths.len() == 1 {
        unique_paths[0].clone()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };

    let mut project_items: Vec<(PathBuf, String)> = projects
        .iter()
        .filter(|(_, report)| !report.artifacts.is_empty())
        .map(|(path, report)| {
            let removable_size: u64 = report
                .artifacts
                .iter()
                .filter(|a| !a.time_filtered)
                .map(|a| a.size)
                .sum();
            let relative = path
                .strip_prefix(&start_path)
                .unwrap_or(path)
                .display()
                .to_string();
            let display = if relative.is_empty() {
                ".".to_string()
            } else {
                relative
            };
            let label = if calculate_sizes {
                format!("{} ({})", display, format_size(removable_size, BINARY))
            } else {
                display
            };
            (path.clone(), label)
        })
        .collect();
    project_items.sort_by(|a, b| a.1.cmp(&b.1));

    let prompt_options: Vec<String> = project_items
        .iter()
        .map(|(_, label)| label.clone())
        .collect();
    let defaults: Vec<usize> = (0..prompt_options.len()).collect();

    let selected_labels = match MultiSelect::new("Select projects to clean:", prompt_options)
        .with_default(&defaults)
        .prompt()
    {
        Ok(selection) => selection,
        Err(inquire::InquireError::OperationCanceled)
        | Err(inquire::InquireError::OperationInterrupted) => {
            return Ok(None);
        }
        Err(err) => return Err(err.into()),
    };

    let selected_paths: HashSet<PathBuf> = selected_labels
        .iter()
        .filter_map(|label| {
            project_items
                .iter()
                .find(|(_, l)| *l == **label)
                .map(|(path, _)| path.clone())
        })
        .collect();

    Ok(Some(selected_paths))
}

/// Build the final confirmation prompt shown after interactive project selection.
/// `total_bytes` is None when sizes were not calculated.
fn confirmation_prompt(
    artifact_count: usize,
    project_count: usize,
    total_bytes: Option<u64>,
) -> String {
    match total_bytes {
        Some(bytes) => format!(
            "Delete {} artifact(s) across {} project(s), {}?",
            artifact_count,
            project_count,
            format_size(bytes, BINARY)
        ),
        None => format!(
            "Delete {} artifact(s) across {} project(s)?",
            artifact_count, project_count
        ),
    }
}

/// Print the outcome of a deletion run (instead of redisplaying the scan table)
fn print_execution_summary(
    projects: &HashMap<PathBuf, ProjectReport>,
    selected: &HashSet<PathBuf>,
    summary: &ExecutionSummary,
    calculate_sizes: bool,
) {
    let projects_cleaned = projects
        .iter()
        .filter(|(path, report)| {
            selected.contains(*path) && report.artifacts.iter().any(|a| a.removed)
        })
        .count();
    let projects_skipped = projects
        .iter()
        .filter(|(path, report)| !selected.contains(*path) && !report.artifacts.is_empty())
        .count();

    println!(
        "Removed {} artifact(s) across {} project(s); skipped {} project(s).",
        summary.artifacts_removed, projects_cleaned, projects_skipped
    );
    if calculate_sizes {
        println!(
            "Total Size Removed: {}",
            format_size(summary.bytes_removed, BINARY).bold().red()
        );
    }
    if summary.failures > 0 {
        println!("{} removal(s) failed.", summary.failures);
    }
}

/// The three-way choice presented in the single interactive deletion prompt.
enum InitialDeletionChoice {
    No,
    YesDeleteAll,
    ChooseProjects,
}

impl std::fmt::Display for InitialDeletionChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitialDeletionChoice::No => write!(f, "No"),
            InitialDeletionChoice::YesDeleteAll => write!(f, "Yes, delete all"),
            InitialDeletionChoice::ChooseProjects => write!(f, "Choose projects…"),
        }
    }
}

/// Outcome of the interactive deletion flow shared by `--delete` and a plain
/// terminal scan that offers to delete.
enum DeletionFlowOutcome {
    /// The user cancelled, selected nothing, or declined the confirmation.
    Cancelled,
    /// Deletion was executed; the summary is returned.
    Deleted(ExecutionSummary),
}

/// Prompt, execute, and summarize deletion. This is the single path used for
/// both `--delete` and a plain scan that offers to delete interactively.
fn run_interactive_deletion(
    projects: &mut HashMap<PathBuf, ProjectReport>,
    unique_paths: &[PathBuf],
    calculate_sizes: bool,
    yes: bool,
    verbose: bool,
) -> Result<DeletionFlowOutcome> {
    let selected = if yes {
        projects.keys().cloned().collect()
    } else {
        let artifact_count = projects
            .values()
            .flat_map(|report| &report.artifacts)
            .filter(|artifact| !artifact.time_filtered)
            .count();
        let total_bytes = if calculate_sizes {
            Some(
                projects
                    .values()
                    .flat_map(|report| &report.artifacts)
                    .filter(|artifact| !artifact.time_filtered)
                    .map(|artifact| artifact.size)
                    .sum(),
            )
        } else {
            None
        };
        let prompt = confirmation_prompt(artifact_count, projects.len(), total_bytes);
        let options = vec![
            InitialDeletionChoice::No,
            InitialDeletionChoice::YesDeleteAll,
            InitialDeletionChoice::ChooseProjects,
        ];
        let choice = match Select::new(&prompt, options).prompt() {
            Ok(choice) => choice,
            Err(inquire::InquireError::OperationCanceled)
            | Err(inquire::InquireError::OperationInterrupted) => {
                return Ok(DeletionFlowOutcome::Cancelled);
            }
            Err(err) => return Err(err.into()),
        };
        match choice {
            InitialDeletionChoice::No => return Ok(DeletionFlowOutcome::Cancelled),
            InitialDeletionChoice::YesDeleteAll => projects.keys().cloned().collect(),
            InitialDeletionChoice::ChooseProjects => {
                match select_projects_interactively(projects, unique_paths, calculate_sizes)? {
                    Some(selected) => selected,
                    None => return Ok(DeletionFlowOutcome::Cancelled),
                }
            }
        }
    };

    if selected.is_empty() {
        return Ok(DeletionFlowOutcome::Cancelled);
    }

    let summary = execute_plan(projects, &selected, verbose);
    print_execution_summary(projects, &selected, &summary, calculate_sizes);

    Ok(DeletionFlowOutcome::Deleted(summary))
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.calculate_sizes {
        eprintln!("cleanslate: --calculate-sizes is now the default; the flag is ignored");
    }
    let calculate_sizes = !args.no_sizes;
    // Captured once so every displayed age is relative to the same instant
    let now = SystemTime::now();

    // Deletion without --yes requires an interactive confirmation prompt; refuse when
    // there is no terminal to prompt on.
    if should_refuse_non_interactive_delete(
        args.delete,
        args.yes,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    ) {
        eprintln!(
            "cleanslate: refusing to delete without a confirmation prompt; pass --yes to confirm"
        );
        std::process::exit(1);
    }

    // Stage 1: scan (pure - never deletes)
    let options = ScanOptions {
        verbose: args.verbose,
        calculate_sizes,
    };
    let (mut result, unique_paths) = scan_for_artifacts(
        &args.paths,
        options,
        args.aggressive,
        args.exclude.clone(),
        args.older_than.clone(),
        args.modified_before.clone(),
    )?;

    let time_filter =
        TimeFilter::from_args(args.older_than.as_deref(), args.modified_before.as_deref())?;
    let report = Report {
        projects: &result.projects,
        unique_paths: &unique_paths,
        time_filter: &time_filter,
        total_bytes: result.total_bytes,
        stats: &result.stats,
        calculate_sizes,
        now,
    };

    // Preview modes: a plain scan IS the preview; --dry-run is the same preview
    // without the deletion hint. When running in a terminal, a plain scan can
    // also offer to enter the same interactive deletion path that --delete uses.
    let has_removable = has_removable_artifacts(&result.projects);

    if !args.delete {
        display_results(&report, args.list);
        print_vcs_failure_notice(&result.stats, args.verbose);
        if args.dry_run {
            println!("Dry run: no files were deleted.");
        } else if should_offer_deletion(
            args.delete,
            args.dry_run,
            std::io::stdout().is_terminal(),
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
            has_removable,
        ) {
            match run_interactive_deletion(
                &mut result.projects,
                &unique_paths,
                calculate_sizes,
                args.yes,
                args.verbose,
            )? {
                DeletionFlowOutcome::Cancelled => println!("No artifacts deleted."),
                DeletionFlowOutcome::Deleted(summary) => {
                    if summary.failures > 0 {
                        std::process::exit(1);
                    }
                }
            }
        } else if has_removable {
            print_delete_command(&DeleteCommand {
                paths: &args.paths,
                older_than: &args.older_than,
                modified_before: &args.modified_before,
                aggressive: args.aggressive,
                exclude: &args.exclude,
            });
        }
        return Ok(());
    }

    if result
        .projects
        .values()
        .all(|report| report.artifacts.is_empty())
    {
        display_results(&report, args.list);
        print_vcs_failure_notice(&result.stats, args.verbose);
        return Ok(());
    }

    match run_interactive_deletion(
        &mut result.projects,
        &unique_paths,
        calculate_sizes,
        args.yes,
        args.verbose,
    )? {
        DeletionFlowOutcome::Cancelled => println!("No artifacts deleted."),
        DeletionFlowOutcome::Deleted(summary) => {
            if summary.failures > 0 {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        confirmation_prompt, remove_overlapping_paths, should_offer_deletion,
        should_refuse_non_interactive_delete,
    };
    use std::path::PathBuf;

    #[test]
    fn confirmation_prompt_includes_size_when_calculated() {
        let prompt = confirmation_prompt(3, 1, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(prompt, "Delete 3 artifact(s) across 1 project(s), 2 GiB?");
    }

    #[test]
    fn confirmation_prompt_omits_size_without_calculated_sizes() {
        let prompt = confirmation_prompt(3, 2, None);
        assert_eq!(prompt, "Delete 3 artifact(s) across 2 project(s)?");
    }

    #[test]
    fn overlapping_scan_paths_keep_only_the_ancestor() {
        let paths = vec![
            PathBuf::from("/workspace/project/target"),
            PathBuf::from("/workspace/project"),
            PathBuf::from("/workspace/other"),
        ];

        let result = remove_overlapping_paths(paths);

        assert_eq!(result.len(), 2);
        assert!(result.contains(&PathBuf::from("/workspace/project")));
        assert!(result.contains(&PathBuf::from("/workspace/other")));
    }

    #[test]
    fn should_offer_deletion_when_all_conditions_hold() {
        assert!(should_offer_deletion(false, false, true, true, true, true));
    }

    #[test]
    fn should_not_offer_deletion_when_delete_is_passed() {
        assert!(!should_offer_deletion(true, false, true, true, true, true));
    }

    #[test]
    fn should_not_offer_deletion_when_dry_run_is_passed() {
        assert!(!should_offer_deletion(false, true, true, true, true, true));
    }

    #[test]
    fn should_not_offer_deletion_when_any_stream_is_not_a_tty() {
        assert!(!should_offer_deletion(
            false, false, false, true, true, true
        ));
        assert!(!should_offer_deletion(
            false, false, true, false, true, true
        ));
        assert!(!should_offer_deletion(
            false, false, true, true, false, true
        ));
    }

    #[test]
    fn should_not_offer_deletion_when_nothing_is_removable() {
        assert!(!should_offer_deletion(
            false, false, true, true, true, false
        ));
    }

    #[test]
    fn should_refuse_non_interactive_delete_when_not_a_tty() {
        assert!(should_refuse_non_interactive_delete(
            true, false, false, true
        ));
        assert!(should_refuse_non_interactive_delete(
            true, false, true, false
        ));
    }

    #[test]
    fn should_not_refuse_when_yes_is_passed() {
        assert!(!should_refuse_non_interactive_delete(
            true, true, false, false
        ));
    }

    #[test]
    fn should_not_refuse_when_delete_is_not_passed() {
        assert!(!should_refuse_non_interactive_delete(
            false, false, false, false
        ));
    }
}
