//! Artifact pattern loading and matching from artifacts.toml.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Files and directories that identify a directory as a project root.
/// Used by pattern matching to decide whether root-scoped patterns (e.g., `/build`)
/// apply and by project discovery to stop descending into subprojects.
pub const PROJECT_ROOT_INDICATORS: &[&str] = &[
    "Cargo.toml",       // Rust
    "pyproject.toml",   // Python
    "package.json",     // JavaScript/Node
    "go.mod",           // Go
    "Gemfile",          // Ruby
    "pom.xml",          // Java/Maven
    "build.gradle",     // Java/Gradle
    "build.gradle.kts", // Java/Gradle Kotlin DSL
    "CMakeLists.txt",   // C/C++ CMake
    "pubspec.yaml",     // Dart/Flutter
    "Package.swift",    // Swift
    "composer.json",    // PHP
    "mix.exs",          // Elixir
    ".git",             // Generic project indicator
    ".jj",              // Jujutsu VCS
];

/// Define artifact types for better classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactType {
    Cache,        // Cache directories that are safe to delete
    Dependency,   // Dependency directories (node_modules, etc.)
    Build,        // Build artifacts (dist, build, etc.)
    Temp,         // Temporary files (.DS_Store, etc.)
    Logs,         // Log files
    Intermediate, // Intermediate files (*.pyc, etc.)
    IDE,          // IDE files (.vscode, .idea, etc.)
}

/// A precompiled matcher for an artifact pattern.
#[derive(Debug, Clone)]
pub enum PatternMatcher {
    /// Matches only the file or directory name at any depth (e.g., `*.pyc`, `node_modules`).
    Filename(globset::GlobMatcher),
    /// Matches a suffix of the full path (e.g., `vendor/bundle`, `*.xcworkspace/xcuserdata`).
    PathSuffix(globset::GlobMatcher),
}

/// Structure to hold artifact pattern and its type
#[derive(Debug, Clone)]
pub struct ArtifactPattern {
    pub pattern: String,
    pub artifact_type: ArtifactType,
    /// Is this a standalone pattern or should it be properly contextualized?
    /// For example, "dist" should only match at the project root level, not any directory named "dist"
    pub needs_context: bool,
    /// The name of the language this pattern belongs to (e.g., "Python", "JavaScript")
    pub language_name: String,
    /// Whether this pattern should only be used in aggressive mode
    pub aggressive: bool,
    /// Precompiled glob matcher for this pattern.
    pub matcher: PatternMatcher,
}

/// Structure to deserialize artifact patterns from TOML
#[derive(Debug, Deserialize)]
struct ArtifactConfig {
    #[serde(flatten)]
    languages: HashMap<String, LanguageConfig>,
}

#[derive(Debug, Deserialize)]
struct LanguageConfig {
    name: String,
    #[serde(flatten)]
    types: HashMap<String, PatternConfig>,
}

#[derive(Debug, Deserialize)]
struct PatternConfig {
    patterns: Vec<String>,
    #[serde(default)]
    aggressive: bool,
}

// Embed the TOML file directly in the binary at compile time
const ARTIFACTS_TOML: &str = include_str!("../artifacts.toml");

/// Compile a single artifact pattern into a matcher.
///
/// - Root-scoped patterns (`needs_context == true`) are matched against the file/directory
///   name; the caller must verify the parent directory is a project root.
/// - Multi-component patterns are matched against the suffix of the full path.
/// - Single-component patterns are matched against the file/directory name only.
fn compile_pattern(pattern: &str, needs_context: bool) -> Result<PatternMatcher> {
    if needs_context {
        // Root-scoped patterns currently are all single-component names.
        let glob = globset::Glob::new(pattern)
            .with_context(|| format!("Invalid root-scoped artifact pattern: {}", pattern))?;
        Ok(PatternMatcher::Filename(glob.compile_matcher()))
    } else if pattern.contains('/') {
        // Multi-component pattern: match as a path suffix.
        let glob = globset::Glob::new(&format!("**/{}", pattern))
            .with_context(|| format!("Invalid multi-component artifact pattern: {}", pattern))?;
        Ok(PatternMatcher::PathSuffix(glob.compile_matcher()))
    } else {
        // Single-component pattern: match only the file/directory name at any depth.
        let glob = globset::Glob::new(pattern)
            .with_context(|| format!("Invalid artifact pattern: {}", pattern))?;
        Ok(PatternMatcher::Filename(glob.compile_matcher()))
    }
}

/// Directories that are conventionally recreatable from manifest files and rarely tracked.
/// These directories can be spot-checked for tracking (single VCS call) rather than
/// checking every file individually.
/// See docs/architecture.md for detailed explanation of the three directory categories.
pub const RECREATABLE_DIRS: &[&str] = &[
    // JavaScript/Node.js
    "node_modules",
    ".npm",
    ".pnpm",
    ".yarn",
    // Python
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".pyright_cache",
    ".tox",
    ".nox",
    ".eggs",
    ".ipynb_checkpoints",
    // Rust
    "target",
    // Java/JVM
    ".gradle",
    ".m2",
    // Ruby
    ".bundle",
    "vendor/bundle",
    // Dart/Flutter
    ".dart_tool",
    ".pub-cache",
    ".flutter-plugins",
    // Haskell
    ".stack-work",
    "dist-newstyle",
    // Go
    ".gocache",
    ".gomodcache",
    "vendor",
    // C/C++
    "CMakeFiles",
    // General build/cache
    ".cache",
    ".parcel-cache",
    ".vite-cache",
    ".rollup-cache",
    ".turbo",
];

/// Helper function to check if a path matches any recreatable directory pattern
pub fn is_recreatable_dir(path: &Path) -> bool {
    // Get the directory name for simple comparisons
    let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    for pattern in RECREATABLE_DIRS {
        if pattern.contains('/') {
            // Multi-component pattern like "vendor/bundle": match the path suffix by
            // components so that an ancestor named "avendor" does not accidentally match.
            if path.ends_with(pattern) {
                return true;
            }
        } else if *pattern == dir_name {
            // Simple exact match
            return true;
        }
    }

    false
}

/// Parse artifact patterns from the embedded TOML content
fn get_artifact_patterns_from_toml() -> Result<Vec<ArtifactPattern>> {
    // Parse the TOML content
    let config: ArtifactConfig =
        toml::from_str(ARTIFACTS_TOML).context("Failed to parse artifacts TOML file")?;

    let mut patterns = Vec::new();

    // Process each language and its artifact types
    for (_lang_key, lang_config) in config.languages {
        // Process each artifact type (cache, build, etc.)
        for (type_key, pattern_config) in lang_config.types {
            // Determine the artifact type based on the TOML key
            // Support variants like "temp_small" by matching prefix
            let artifact_type = if type_key.starts_with("cache") {
                ArtifactType::Cache
            } else if type_key.starts_with("dependencies") {
                ArtifactType::Dependency
            } else if type_key.starts_with("build") {
                ArtifactType::Build
            } else if type_key.starts_with("temp") {
                ArtifactType::Temp
            } else if type_key.starts_with("logs") {
                ArtifactType::Logs
            } else if type_key.starts_with("intermediate") {
                ArtifactType::Intermediate
            } else if type_key.starts_with("ide") {
                ArtifactType::IDE
            } else {
                eprintln!(
                    "Warning: Unknown artifact type '{}', defaulting to Cache",
                    type_key
                );
                ArtifactType::Cache
            };

            // Process each pattern
            for pattern in pattern_config.patterns {
                // Patterns starting with / need context (they only match at project root)
                let needs_context = pattern.starts_with('/');

                // If the pattern starts with /, remove it for the actual matching
                let pattern_normalized = if needs_context {
                    pattern.strip_prefix('/').unwrap_or(&pattern).to_string()
                } else {
                    pattern
                };

                let matcher = compile_pattern(&pattern_normalized, needs_context)?;

                patterns.push(ArtifactPattern {
                    pattern: pattern_normalized,
                    artifact_type,
                    needs_context,
                    language_name: lang_config.name.clone(),
                    aggressive: pattern_config.aggressive,
                    matcher,
                });
            }
        }
    }

    Ok(patterns)
}

/// Load artifact patterns from TOML
pub fn load_artifact_patterns() -> Result<Vec<ArtifactPattern>> {
    get_artifact_patterns_from_toml()
}

/// Get artifact patterns, optionally filtering by aggressive mode
pub fn get_artifact_patterns(aggressive: bool) -> Result<Vec<ArtifactPattern>> {
    let all_patterns = load_artifact_patterns()?;

    // Filter out aggressive-only patterns if not in aggressive mode
    let patterns = if aggressive {
        all_patterns
    } else {
        all_patterns.into_iter().filter(|p| !p.aggressive).collect()
    };

    Ok(patterns)
}

/// Return the pattern that classifies `path` as an artifact, if any.
/// Uses a whitelist approach - only paths that explicitly match known artifact patterns match.
pub fn matching_pattern<'a>(
    path: &Path,
    patterns: &'a [ArtifactPattern],
) -> Option<&'a ArtifactPattern> {
    let filename = path.file_name()?;

    for pattern in patterns {
        match &pattern.matcher {
            PatternMatcher::Filename(matcher) => {
                // Match against the candidate's own file/directory name only; ancestors
                // coincidentally named "tmp", "env", etc. must not cause a match.
                if matcher.is_match(Path::new(filename)) {
                    if pattern.needs_context {
                        // Root-scoped patterns require the parent directory to be a project root.
                        if let Some(parent) = path.parent() {
                            if is_project_root(parent) {
                                return Some(pattern);
                            }
                        }
                    } else {
                        return Some(pattern);
                    }
                }
            }
            PatternMatcher::PathSuffix(matcher) => {
                if matcher.is_match(path) {
                    return Some(pattern);
                }
            }
        }
    }

    // Default to no match - only explicit matches are considered artifacts
    None
}

/// Check if a path is an artifact based on the patterns
/// Uses a whitelist approach - only returns true for paths that explicitly match known artifact patterns
pub fn is_artifact(path: &Path, patterns: &[ArtifactPattern]) -> bool {
    matching_pattern(path, patterns).is_some()
}

/// Helper function to check if a path is a project root
pub fn is_project_root(path: &Path) -> bool {
    PROJECT_ROOT_INDICATORS
        .iter()
        .any(|indicator| path.join(indicator).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pattern(raw: &str) -> ArtifactPattern {
        let needs_context = raw.starts_with('/');
        let normalized = if needs_context {
            raw.strip_prefix('/').unwrap_or(raw).to_string()
        } else {
            raw.to_string()
        };
        ArtifactPattern {
            pattern: normalized.clone(),
            artifact_type: ArtifactType::Temp,
            needs_context,
            language_name: "Test".to_string(),
            aggressive: false,
            matcher: compile_pattern(&normalized, needs_context).unwrap(),
        }
    }

    #[test]
    fn multi_star_pattern_matches() {
        let patterns = vec![make_pattern("cmake-build-*-debug")];
        assert!(is_artifact(
            Path::new("/project/cmake-build-x86_64-debug"),
            &patterns
        ));
        assert!(!is_artifact(
            Path::new("/project/cmake-build-debug"),
            &patterns
        ));
        assert!(!is_artifact(
            Path::new("/project/cmake-build-x86_64-release"),
            &patterns
        ));
    }

    #[test]
    fn multi_star_suffix_pattern_matches() {
        let patterns = vec![make_pattern("*.tmp.*")];
        assert!(is_artifact(Path::new("/project/file.tmp.txt"), &patterns));
        assert!(is_artifact(Path::new("/project/archive.tmp.gz"), &patterns));
        assert!(!is_artifact(Path::new("/project/file.tmp"), &patterns));
        assert!(!is_artifact(Path::new("/project/file.txt"), &patterns));
    }

    #[test]
    fn filename_only_does_not_match_ancestor_dirs() {
        let patterns = vec![make_pattern("tmp"), make_pattern("*.pyc")];
        assert!(is_artifact(Path::new("/project/tmp"), &patterns));
        assert!(!is_artifact(Path::new("/project/tmp/file.txt"), &patterns));
        assert!(is_artifact(Path::new("/project/module.pyc"), &patterns));
        assert!(!is_artifact(
            Path::new("/project/module.pyc/file.txt"),
            &patterns
        ));
    }

    #[test]
    fn multi_component_path_suffix_matches() {
        let patterns = vec![
            make_pattern("vendor/bundle"),
            make_pattern("*.xcworkspace/xcuserdata"),
        ];
        assert!(is_artifact(Path::new("/project/vendor/bundle"), &patterns));
        assert!(!is_artifact(
            Path::new("/project/avendor/bundle"),
            &patterns
        ));
        assert!(is_artifact(
            Path::new("/project/MyApp.xcworkspace/xcuserdata"),
            &patterns
        ));
        assert!(!is_artifact(
            Path::new("/project/MyApp.xcworkspace"),
            &patterns
        ));
    }

    #[test]
    fn root_scoped_pattern_requires_project_root() {
        let patterns = vec![make_pattern("/build")];
        assert!(!is_artifact(Path::new("/parent/build"), &patterns));
    }

    #[test]
    fn is_recreatable_dir_matches_vendor_bundle() {
        assert!(is_recreatable_dir(Path::new("/project/vendor/bundle")));
        assert!(!is_recreatable_dir(Path::new("/project/avendor/bundle")));
    }
}
