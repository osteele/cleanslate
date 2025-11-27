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

#[cfg(test)]
mod tests {
    use super::*;

    // ============ parse_duration tests ============

    #[test]
    fn test_parse_duration_default_days() {
        let duration = parse_duration("15").unwrap();
        assert_eq!(duration.as_secs(), 15 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_explicit_days() {
        let duration = parse_duration("15d").unwrap();
        assert_eq!(duration.as_secs(), 15 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_days_uppercase() {
        let duration = parse_duration("15D").unwrap();
        assert_eq!(duration.as_secs(), 15 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_hours() {
        let duration = parse_duration("48h").unwrap();
        assert_eq!(duration.as_secs(), 48 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_hours_uppercase() {
        let duration = parse_duration("48H").unwrap();
        assert_eq!(duration.as_secs(), 48 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_weeks() {
        let duration = parse_duration("2w").unwrap();
        assert_eq!(duration.as_secs(), 2 * 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_weeks_uppercase() {
        let duration = parse_duration("2W").unwrap();
        assert_eq!(duration.as_secs(), 2 * 7 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_months() {
        let duration = parse_duration("3m").unwrap();
        assert_eq!(duration.as_secs(), 3 * 30 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_months_uppercase() {
        let duration = parse_duration("3M").unwrap();
        assert_eq!(duration.as_secs(), 3 * 30 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_zero() {
        let duration = parse_duration("0d").unwrap();
        assert_eq!(duration.as_secs(), 0);
    }

    #[test]
    fn test_parse_duration_invalid_unit() {
        let result = parse_duration("15x");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid duration unit"));
    }

    #[test]
    fn test_parse_duration_invalid_number() {
        let result = parse_duration("abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected a number"));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        let duration = parse_duration("  15d  ").unwrap();
        assert_eq!(duration.as_secs(), 15 * 24 * 60 * 60);
    }

    // ============ parse_date tests ============

    #[test]
    fn test_parse_date_valid() {
        let result = parse_date("2025-01-15");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_date_leap_year() {
        let result = parse_date("2000-02-29");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_date_invalid_format() {
        let result = parse_date("01-15-2025");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid date format"));
    }

    #[test]
    fn test_parse_date_invalid_date() {
        let result = parse_date("2025-02-30");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_date_year_too_old() {
        let result = parse_date("1900-01-01");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Year must be between"));
    }

    #[test]
    fn test_parse_date_year_too_new() {
        let result = parse_date("2200-01-01");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Year must be between"));
    }

    #[test]
    fn test_parse_date_boundary_years() {
        assert!(parse_date("1970-01-01").is_ok());
        assert!(parse_date("2100-12-31").is_ok());
    }

    // ============ TimeFilter tests ============

    #[test]
    fn test_time_filter_inactive() {
        let filter = TimeFilter::from_args(None, None).unwrap();
        assert!(!filter.is_active());
    }

    #[test]
    fn test_time_filter_older_than_active() {
        let filter = TimeFilter::from_args(Some("7d"), None).unwrap();
        assert!(filter.is_active());
    }

    #[test]
    fn test_time_filter_modified_before_active() {
        let filter = TimeFilter::from_args(None, Some("2025-01-01")).unwrap();
        assert!(filter.is_active());
    }

    #[test]
    fn test_time_filter_both_active() {
        let filter = TimeFilter::from_args(Some("7d"), Some("2025-01-01")).unwrap();
        assert!(filter.is_active());
    }

    #[test]
    fn test_time_filter_passes_no_filter() {
        let filter = TimeFilter::from_args(None, None).unwrap();
        let now = SystemTime::now();
        assert!(filter.passes(now));
    }

    #[test]
    fn test_time_filter_passes_old_file() {
        let filter = TimeFilter::from_args(Some("7d"), None).unwrap();
        // A file from 30 days ago should pass
        let old_time = SystemTime::now() - Duration::from_secs(30 * 24 * 60 * 60);
        assert!(filter.passes(old_time));
    }

    #[test]
    fn test_time_filter_fails_new_file() {
        let filter = TimeFilter::from_args(Some("7d"), None).unwrap();
        // A file from 1 day ago should fail (too new)
        let new_time = SystemTime::now() - Duration::from_secs(1 * 24 * 60 * 60);
        assert!(!filter.passes(new_time));
    }

    #[test]
    fn test_time_filter_stats_default() {
        let stats = TimeFilterStats::default();
        assert_eq!(stats.total_found, 0);
        assert_eq!(stats.passed_time_filter, 0);
        assert_eq!(stats.excluded_by_time, 0);
    }
}
