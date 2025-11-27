//! Artifact pattern loading and matching from artifacts.toml.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

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

/// Structure to hold artifact pattern and its type
#[derive(Debug, Clone)]
pub struct ArtifactPattern {
    pub pattern: String,
    #[allow(dead_code)]
    pub artifact_type: ArtifactType,
    /// Is this a standalone pattern or should it be properly contextualized?
    /// For example, "dist" should only match at the project root level, not any directory named "dist"
    pub needs_context: bool,
    /// The name of the language this pattern belongs to (e.g., "Python", "JavaScript")
    pub language_name: String,
    /// Whether this pattern should only be used in aggressive mode
    pub aggressive: bool,
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
            // Multi-component pattern like "vendor/bundle"
            if matches_path_suffix(path, pattern) {
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

                patterns.push(ArtifactPattern {
                    pattern: pattern_normalized,
                    artifact_type,
                    needs_context,
                    language_name: lang_config.name.clone(),
                    aggressive: pattern_config.aggressive,
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

/// Check if a path is an artifact based on the patterns
/// Uses a whitelist approach - only returns true for paths that explicitly match known artifact patterns
pub fn is_artifact(path: &Path, patterns: &[ArtifactPattern]) -> bool {
    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy())
        .unwrap_or_default();

    // Now apply whitelist pattern matching - ONLY return true if we match a known artifact pattern
    for pattern in patterns {
        // Handle patterns that need context (starting with /)
        if pattern.needs_context {
            // For root-scoped patterns, we need to check if the filename matches
            // and if the parent directory is a project root
            if filename == pattern.pattern {
                // Check if parent is a project root
                if let Some(parent) = path.parent() {
                    if is_project_root(parent) {
                        return true;
                    }
                }
            }
            continue;
        }

        // Check if pattern contains a slash (multi-component pattern)
        if pattern.pattern.contains('/') {
            // Multi-component pattern like "vendor/bundle" or "*.xcworkspace/xcuserdata"
            if matches_path_suffix(path, &pattern.pattern) {
                return true;
            }
            continue;
        }

        // Single-component patterns - check different pattern types
        if let Some(suffix) = pattern.pattern.strip_prefix('*') {
            // Match against filename for suffix patterns (e.g., *.pyc)
            if filename.ends_with(suffix) {
                return true;
            }
        } else if pattern.pattern.contains('*') {
            // Handle glob patterns - match against filename only
            let parts: Vec<&str> = pattern.pattern.split('*').collect();
            if parts.len() == 2 {
                let filename_str = filename.to_string();
                if filename_str.starts_with(parts[0]) && filename_str.ends_with(parts[1]) {
                    return true;
                }
            }
        } else if filename == pattern.pattern {
            // Exact filename match
            return true;
        } else {
            // Component-based matching: check if pattern matches any path component
            // This prevents false positives like "logs" matching "/catalogs/"
            if path.components().any(|c| {
                if let std::path::Component::Normal(os_str) = c {
                    os_str.to_string_lossy() == pattern.pattern
                } else {
                    false
                }
            }) {
                return true;
            }
        }
    }

    // Default to false - only explicit matches are considered artifacts
    false
}

/// Helper function to match multi-component patterns against path suffixes
/// Supports wildcards like "*.xcworkspace/xcuserdata" and literals like "vendor/bundle"
fn matches_path_suffix(path: &Path, pattern: &str) -> bool {
    // Split the pattern into components
    let pattern_parts: Vec<&str> = pattern.split('/').collect();

    // Get path components from the end
    let path_components: Vec<_> = path
        .components()
        .filter_map(|c| {
            if let std::path::Component::Normal(os_str) = c {
                Some(os_str.to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect();

    // Check if we have enough components to match
    if path_components.len() < pattern_parts.len() {
        return false;
    }

    // Match from the end of the path
    let start_idx = path_components.len() - pattern_parts.len();
    for (i, pattern_part) in pattern_parts.iter().enumerate() {
        let path_component = &path_components[start_idx + i];

        if !matches_component(path_component, pattern_part) {
            return false;
        }
    }

    true
}

/// Helper function to match a single path component against a pattern with wildcards
fn matches_component(component: &str, pattern: &str) -> bool {
    if pattern == component {
        // Exact match
        return true;
    }

    if !pattern.contains('*') && !pattern.contains('?') {
        // No wildcards, already checked exact match above
        return false;
    }

    // Handle wildcards
    if let Some(suffix) = pattern.strip_prefix('*') {
        // Simple suffix match like "*.xcworkspace"
        return component.ends_with(suffix);
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        // Simple prefix match like "cmake-build-*"
        return component.starts_with(prefix);
    }

    // Complex glob pattern - split on * and match parts
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        return component.starts_with(parts[0]) && component.ends_with(parts[1]);
    }

    // For more complex patterns, we'd need a full glob matcher
    // For now, return false for patterns we can't handle
    false
}

/// Helper function to check if a path is a project root
pub fn is_project_root(path: &Path) -> bool {
    let indicators = [
        "Cargo.toml",     // Rust
        "pyproject.toml", // Python
        "package.json",   // JavaScript/Node
        "go.mod",         // Go
        ".git",           // Generic project indicator
        ".jj",            // Jujutsu VCS
    ];

    for indicator in &indicators {
        if path.join(indicator).exists() {
            return true;
        }
    }

    false
}
