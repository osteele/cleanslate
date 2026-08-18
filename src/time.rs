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
    pub fn from_args(
        older_than_str: Option<&str>,
        modified_before_str: Option<&str>,
    ) -> Result<Self> {
        let older_than = if let Some(duration_str) = older_than_str {
            let duration = parse_duration(duration_str)?;
            let cutoff = SystemTime::now().checked_sub(duration).with_context(|| {
                format!(
                    "Duration '{}' reaches before the representable past",
                    duration_str
                )
            })?;
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

    /// Build a filter directly from cutoffs. `older_than` keeps only files
    /// strictly older than the cutoff; `modified_before` keeps only files
    /// strictly earlier than the cutoff.
    pub fn from_cutoffs(
        older_than: Option<SystemTime>,
        modified_before: Option<SystemTime>,
    ) -> Self {
        TimeFilter {
            older_than,
            modified_before,
        }
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

/// Format the age of an artifact compactly and human-readably.
/// Returns "today" for under 24 hours, then "Nd", "Nw", "Nmo", or "Ny"
/// as the age crosses each boundary. A modification time in the future
/// (clock skew) is treated as "today".
pub fn format_age(modified: SystemTime, now: SystemTime) -> String {
    const DAY_SECS: u64 = 24 * 60 * 60;

    let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
    let days = age.as_secs() / DAY_SECS;

    if age.as_secs() < DAY_SECS {
        "today".to_string()
    } else if days < 7 {
        format!("{}d", days)
    } else if days < 30 {
        format!("{}w", days / 7)
    } else if days < 365 {
        format!("{}mo", days / 30)
    } else {
        format!("{}y", days / 365)
    }
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

    // Calculate total seconds based on unit, refusing values whose second count
    // overflows u64 instead of panicking (debug) or wrapping (release)
    let seconds = match unit {
        None | Some("d") | Some("D") => {
            // Default to days for backward compatibility
            secs_per(value, 24 * 60 * 60, duration_str)?
        }
        Some("h") | Some("H") => {
            // Hours
            secs_per(value, 60 * 60, duration_str)?
        }
        Some("w") | Some("W") => {
            // Weeks (7 days)
            secs_per(value, 7 * 24 * 60 * 60, duration_str)?
        }
        Some("m") | Some("M") => {
            // Months (approximate as 30 days)
            secs_per(value, 30 * 24 * 60 * 60, duration_str)?
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

fn secs_per(value: u64, unit_secs: u64, duration_str: &str) -> Result<u64> {
    value
        .checked_mul(unit_secs)
        .with_context(|| format!("Duration '{}' is too large to represent", duration_str))
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid duration unit"));
    }

    #[test]
    fn test_parse_duration_invalid_number() {
        let result = parse_duration("abc");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Expected a number"));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        let duration = parse_duration("  15d  ").unwrap();
        assert_eq!(duration.as_secs(), 15 * 24 * 60 * 60);
    }

    #[test]
    fn test_parse_duration_overflow_returns_error_not_panic() {
        // u64::MAX weeks overflows the seconds computation; it must produce a
        // clean error rather than panicking (debug) or wrapping (release).
        let result = parse_duration("18446744073709551615w");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("too large to represent"));
    }

    #[test]
    fn test_time_filter_older_than_reaching_before_epoch_returns_error() {
        // ~58,000 years ago reaches before the SystemTime epoch; must be a
        // clean error, not a panic in the now - duration subtraction.
        let result = TimeFilter::from_args(Some("999999999999999d"), None);
        assert!(result.is_err());
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid date format"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Year must be between"));
    }

    #[test]
    fn test_parse_date_year_too_new() {
        let result = parse_date("2200-01-01");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Year must be between"));
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
        let new_time = SystemTime::now() - Duration::from_secs(24 * 60 * 60);
        assert!(!filter.passes(new_time));
    }

    // ============ modified_before pass/fail contract tests ============

    #[test]
    fn test_time_filter_modified_before_passes_old_file() {
        let cutoff = parse_date("2025-01-15").unwrap();
        let filter = TimeFilter::from_args(None, Some("2025-01-15")).unwrap();
        // Modified one second before the cutoff: passes.
        let old_time = cutoff - Duration::from_secs(1);
        assert!(filter.passes(old_time));
    }

    #[test]
    fn test_time_filter_modified_before_fails_new_file() {
        let cutoff = parse_date("2025-01-15").unwrap();
        let filter = TimeFilter::from_args(None, Some("2025-01-15")).unwrap();
        // Modified one second after the cutoff: fails.
        let new_time = cutoff + Duration::from_secs(1);
        assert!(!filter.passes(new_time));
    }

    /// The boundary itself counts as too recent: "modified before" is strict.
    #[test]
    fn test_time_filter_modified_before_boundary_is_excluded() {
        let cutoff = parse_date("2025-01-15").unwrap();
        let filter = TimeFilter::from_args(None, Some("2025-01-15")).unwrap();
        assert!(!filter.passes(cutoff));
    }

    /// The older-than cutoff is likewise strict at the boundary.
    #[test]
    fn test_time_filter_older_than_boundary_is_excluded() {
        let cutoff = SystemTime::now() - Duration::from_secs(7 * 24 * 60 * 60);
        let filter = TimeFilter::from_cutoffs(Some(cutoff), None);
        assert!(!filter.passes(cutoff));
        assert!(filter.passes(cutoff - Duration::from_secs(1)));
    }

    /// The modified-before boundary is strict when built from exact cutoffs.
    #[test]
    fn test_time_filter_modified_before_boundary_from_cutoffs() {
        let cutoff = SystemTime::now() - Duration::from_secs(7 * 24 * 60 * 60);
        let filter = TimeFilter::from_cutoffs(None, Some(cutoff));
        assert!(!filter.passes(cutoff));
        assert!(filter.passes(cutoff - Duration::from_secs(1)));
    }

    /// With both filters active, an artifact must pass both (README: "an
    /// artifact must pass both filters"). Covers each region: passes both,
    /// fails only the age cutoff, fails only the date cutoff, fails both.
    #[test]
    fn test_time_filter_both_filters_require_both_to_pass() {
        let now = SystemTime::now();
        let age_cutoff = now - Duration::from_secs(7 * 24 * 60 * 60);

        // Date cutoff older than the age cutoff: between them, only the date
        // filter fails.
        let date_cutoff_far = now - Duration::from_secs(30 * 24 * 60 * 60);
        let filter = TimeFilter::from_cutoffs(Some(age_cutoff), Some(date_cutoff_far));
        assert!(filter.passes(date_cutoff_far - Duration::from_secs(24 * 60 * 60))); // passes both
        assert!(!filter.passes(now - Duration::from_secs(14 * 24 * 60 * 60))); // fails date only
        assert!(!filter.passes(now - Duration::from_secs(24 * 60 * 60))); // fails both

        // Date cutoff newer than the age cutoff: between them, only the age
        // filter fails.
        let date_cutoff_near = now - Duration::from_secs(24 * 60 * 60);
        let filter = TimeFilter::from_cutoffs(Some(age_cutoff), Some(date_cutoff_near));
        assert!(!filter.passes(now - Duration::from_secs(3 * 24 * 60 * 60))); // fails age only
        assert!(filter.passes(now - Duration::from_secs(60 * 24 * 60 * 60))); // passes both
    }

    // ============ format_age tests ============

    fn age_string(age_secs: u64) -> String {
        let now = SystemTime::now();
        format_age(now - Duration::from_secs(age_secs), now)
    }

    #[test]
    fn test_format_age_today() {
        assert_eq!(age_string(0), "today");
        assert_eq!(age_string(60 * 60), "today");
        assert_eq!(age_string(23 * 60 * 60 + 59 * 60), "today");
    }

    #[test]
    fn test_format_age_days() {
        assert_eq!(age_string(24 * 60 * 60), "1d");
        assert_eq!(age_string(3 * 24 * 60 * 60), "3d");
        assert_eq!(age_string(6 * 24 * 60 * 60), "6d");
    }

    #[test]
    fn test_format_age_weeks() {
        assert_eq!(age_string(7 * 24 * 60 * 60), "1w");
        assert_eq!(age_string(2 * 7 * 24 * 60 * 60), "2w");
        assert_eq!(age_string(29 * 24 * 60 * 60), "4w");
    }

    #[test]
    fn test_format_age_months() {
        assert_eq!(age_string(30 * 24 * 60 * 60), "1mo");
        assert_eq!(age_string(5 * 30 * 24 * 60 * 60), "5mo");
        assert_eq!(age_string(364 * 24 * 60 * 60), "12mo");
    }

    #[test]
    fn test_format_age_years() {
        assert_eq!(age_string(365 * 24 * 60 * 60), "1y");
        assert_eq!(age_string(2 * 365 * 24 * 60 * 60), "2y");
    }

    #[test]
    fn test_format_age_future_is_today() {
        let now = SystemTime::now();
        assert_eq!(format_age(now + Duration::from_secs(60), now), "today");
    }
}
