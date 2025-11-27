//! Time-based filtering logic.

use anyhow::{Context, Result};
use chrono::{Datelike, Local, NaiveDate, TimeZone};
use std::time::{Duration, SystemTime};

/// Time filter configuration for artifact removal
pub struct TimeFilter {
    /// Files must be older than this time to be removed
    older_than: Option<SystemTime>,
    /// Files must be modified before this time to be removed
    modified_before: Option<SystemTime>,
}

impl TimeFilter {
    /// Create a time filter from CLI arguments
    pub fn from_args(older_than_str: Option<&str>, modified_before_str: Option<&str>) -> Result<Self> {
        let older_than = if let Some(duration_str) = older_than_str {
            let duration = parse_duration(duration_str)?;
            let cutoff = SystemTime::now() - duration;
            Some(cutoff)
        } else {
            None
        };

        let modified_before = if let Some(date_str) = modified_before_str {
            Some(parse_date(date_str)?)
        } else {
            None
        };

        Ok(TimeFilter {
            older_than,
            modified_before,
        })
    }

    /// Check if a file passes the time filter
    /// Returns true if the file should be considered for removal based on time
    pub fn passes(&self, modified_time: SystemTime) -> bool {
        if let Some(cutoff) = self.older_than {
            if modified_time >= cutoff {
                // File is too new (modified after cutoff)
                return false;
            }
        }

        if let Some(cutoff) = self.modified_before {
            if modified_time >= cutoff {
                // File was modified on or after the cutoff date
                return false;
            }
        }

        true
    }

    /// Check if any time filters are active
    pub fn is_active(&self) -> bool {
        self.older_than.is_some() || self.modified_before.is_some()
    }
}

/// Context for time-based filtering, including the filter and statistics
pub struct TimeFilterContext<'a> {
    pub filter: &'a TimeFilter,
    pub stats: &'a mut TimeFilterStats,
}

/// Statistics about time-based filtering
#[derive(Debug, Default)]
pub struct TimeFilterStats {
    pub total_found: usize,
    pub passed_time_filter: usize,
    pub excluded_by_time: usize,
}

/// Parse a date string in YYYY-MM-DD format to SystemTime
pub fn parse_date(date_str: &str) -> Result<SystemTime> {
    // Use chrono for robust date parsing with proper validation
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d").with_context(|| {
        format!(
            "Invalid date format. Expected YYYY-MM-DD, got: {}",
            date_str
        )
    })?;

    // NaiveDate doesn't have year limits, so add validation
    let year = date.year();
    if !(1970..=2100).contains(&year) {
        anyhow::bail!("Year must be between 1970 and 2100, got: {}", year);
    }

    // Convert to local midnight, then to SystemTime
    // This interprets the date in the user's local timezone, not UTC
    let naive_datetime = date
        .and_hms_opt(0, 0, 0)
        .context("Failed to create midnight time")?;
    let local_datetime = Local
        .from_local_datetime(&naive_datetime)
        .single()
        .context("Ambiguous or invalid local time")?;

    Ok(local_datetime.into())
}

/// Parse a duration string with optional unit suffix
/// Supports: h (hours), d (days), w (weeks), m (months)
/// Plain numbers default to days for backward compatibility
/// Examples: "15", "15d", "2w", "3m", "48h"
pub fn parse_duration(duration_str: &str) -> Result<Duration> {
    let duration_str = duration_str.trim();

    // Try to extract number and unit
    let (num_str, unit) = if let Some(pos) = duration_str.find(|c: char| c.is_alphabetic()) {
        let (num, unit) = duration_str.split_at(pos);
        (num, Some(unit))
    } else {
        // No unit specified, default to days for backward compatibility
        (duration_str, None)
    };

    // Parse the numeric part
    let value: u64 = num_str.trim().parse().with_context(|| {
        format!(
            "Invalid duration format. Expected a number, got: {}",
            num_str
        )
    })?;

    // Calculate total seconds based on unit
    let seconds = match unit {
        None | Some("d") | Some("D") => {
            // Default to days for backward compatibility
            value * 24 * 60 * 60
        }
        Some("h") | Some("H") => {
            // Hours
            value * 60 * 60
        }
        Some("w") | Some("W") => {
            // Weeks (7 days)
            value * 7 * 24 * 60 * 60
        }
        Some("m") | Some("M") => {
            // Months (approximate as 30 days)
            value * 30 * 24 * 60 * 60
        }
        Some(unknown) => {
            anyhow::bail!(
                "Invalid duration unit '{}'. Supported units: h (hours), d (days), w (weeks), m (months)",
                unknown
            );
        }
    };

    Ok(Duration::from_secs(seconds))
}
