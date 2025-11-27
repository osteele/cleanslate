//! CleanSlate - Selective Artifact Cleaner
//!
//! CleanSlate removes build artifacts and caches based on pattern matching and VCS tracking status.
//! Unlike `git clean` which removes all untracked files, CleanSlate is selective and only removes
//! files that match known artifact patterns (from artifacts.toml) AND are not tracked in version control.
//!
//! ## Architecture
//!
//! See `docs/architecture.md` for complete documentation on:
//! - Layered removal strategy (pattern matching → VCS tracking → directory categorization)
//! - Three-tier directory categorization for performance optimization
//! - VCS tracking vs gitignore semantics (critical distinction!)
//! - Empty directory cleanup strategy

pub mod patterns;
pub mod scanner;
pub mod time;
pub mod vcs;

// Re-export commonly used items
pub use patterns::{get_artifact_patterns, is_artifact, ArtifactPattern, ArtifactType};
pub use scanner::{
    find_project_root, scan_single_path, truncate_name_with_suffix, ArtifactEntry, ProjectReport,
    ScanOptions, ScanResult,
};
pub use time::{TimeFilter, TimeFilterContext, TimeFilterStats};
pub use vcs::{detect_vcs, VcsType};
