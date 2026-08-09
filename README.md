# CleanSlate

A command-line tool that recursively examines directories to find and optionally clean build artifacts and cache files from various programming languages.

## Features

- Scans directories recursively to identify build artifacts and caches
- Preserves files tracked by Git or Jujutsu
- Detects projects by looking for common project indicators
- Groups artifacts by project
- Optionally calculates artifact sizes
- Filters artifacts by age or modification date
- Excludes selected directories by name
- Optionally deletes identified artifacts
- Colorized output

## Supported Languages

CleanSlate identifies common artifacts from:

- **Python**: `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.venv`, `*.pyc`, `*.egg-info`, etc.
- **JavaScript/TypeScript**: `node_modules`, `.next`, `.nuxt`, `.svelte-kit`, `.npm`, `.cache`, etc.
- **Rust**: `.cargo` cache
- **Go**: `/vendor` (at project root)
- **Ruby**: `.bundle`, `vendor/bundle`
- **Swift/Xcode**: `DerivedData`, `/.build`, `*.xcworkspace/xcuserdata`
- **Java/JVM**: `.gradle`, `.m2`, `/classes`
- **C/C++**: `*.o`, `*.so`, `*.dll`, `CMakeFiles`, etc.
- **Dart/Flutter**: `.dart_tool`, `.pub-cache`
- **Haskell**: `.stack-work`, `dist-newstyle`
- **General**: `tmp`, `logs`, `.idea`, and, in aggressive mode, `.DS_Store` and `Thumbs.db`

## Pattern Syntax

CleanSlate uses a pattern system defined in `artifacts.toml`. Understanding the pattern syntax helps you know what will be detected:

### Pattern Types

1. **Root-level patterns** (with `/` prefix): Only match at project root
   - Example: `/build` matches `<project-root>/build` but NOT `<project-root>/src/build`
   - Used for: `/target`, `/dist`, `/out`, `/bin`, `/coverage`, `/vendor`, etc.

2. **Anywhere patterns** (no `/` prefix): Match at any depth
   - Example: `tmp` matches any directory named `tmp` anywhere in the tree
   - Used for: `node_modules`, `__pycache__`, `tmp`, `logs`, `.DS_Store`, etc.

3. **Wildcard patterns**: Simple glob matching
   - Example: `*.pyc` matches any file ending in `.pyc`
   - Example: `yarn-*.log` matches `yarn-debug.log`, `yarn-error.log`, etc.

### Project Root Detection

CleanSlate determines project roots by looking for:
- `Cargo.toml` (Rust)
- `pyproject.toml` (Python)
- `package.json` (JavaScript/Node)
- `go.mod` (Go)
- `.git` (Git repository)
- `.jj` (Jujutsu repository)

This ensures that `/build` patterns only match at the actual project root, not in subdirectories.

## Safety Features

- **Version Control Aware**: Files tracked in Git or Jujutsu are never removed, even if they match artifact patterns
- **VCS Directory Skip**: Never scans inside version control directories (`.git`, `.jj`, `.svn`, `.hg`, `.bzr`, `_darcs`, `.pijul`, `CVS`, `.fossil`)
- **Nested Repository Protection**: Skips artifact directories that contain version control metadata
- **Fail-Closed VCS Checks**: Keeps files when their tracking status cannot be determined
- **Pattern-Based Selection**: Only removes files matching known artifact patterns (from `artifacts.toml`), leaving untracked source files alone
- **Symlink Safe**: Never follows or deletes symlinks
- **Dry Run Mode**: Use `--dry-run` to see what would be deleted without actually deleting

## Important Notes

- **Cargo.lock**: Not treated as an artifact (correctly committed for binary projects)
- **.vscode**: Not treated as an artifact (teams often commit IDE settings)
- **node_modules**: Matches anywhere (supports monorepos with nested packages)

## Installation

```bash
cargo install --git https://github.com/osteele/cleanslate.git
```

Or build from source:

```bash
git clone https://github.com/osteele/cleanslate.git
cd cleanslate
cargo install --path .
```

## Usage

```bash
# Scan current directory (shows table by default)
cleanslate

# Scan specific directories
cleanslate /path/to/dir1 /path/to/dir2

# Preview what would be deleted (dry run)
cleanslate --dry-run

# Show detailed list format instead of table
cleanslate --list

# Calculate artifact sizes
cleanslate --calculate-sizes

# Show diagnostic details while scanning
cleanslate --verbose

# Exclude directories named vendor
cleanslate --exclude vendor

# Find artifacts older than two weeks
cleanslate --older-than 2w

# Delete artifacts
cleanslate --delete
```

## Options

- `[PATHS]...`: Directories to scan (defaults to current directory)
- `-d, --delete`: Delete the found artifacts
- `-v, --verbose`: Show detailed information about found artifacts
- `--dry-run`: Show what would be deleted without actually deleting (implies --delete)
- `-l, --list`: Show detailed list format instead of table (table is default)
- `--aggressive`: Include small or trivial files such as `.DS_Store`
- `-x, --exclude <DIR>`: Exclude directories by name; may be repeated
- `--older-than <DURATION>`: Include artifacts older than a duration such as `48h`, `15d`, `2w`, or `3m`; plain numbers mean days
- `--modified-before <DATE>`: Include artifacts modified before a date in `YYYY-MM-DD` format
- `--calculate-sizes`: Calculate artifact sizes by traversing directories
- `-h, --help`: Print help
- `-V, --version`: Print version

## Output Format

By default, CleanSlate displays a table with these columns:

- **Path**: Relative path from scan directory
- **What**: Artifacts that would be removed

Use `--calculate-sizes` to add a **Removable** column. An active time filter also adds a **Too Recent** column. Removable totals over 100 MiB are highlighted, and individual artifacts over 50 MiB are shown in bold.

Use `--list` for a per-project breakdown grouped by language or tool.

## License

MIT License

## Author

Oliver Steele
