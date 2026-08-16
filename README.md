# CleanSlate

CleanSlate recursively examines directories to find and optionally remove build artifacts and cache files from several programming languages.

## Features

- Scans directories recursively to identify build artifacts and caches
- Preserves files tracked by Git or Jujutsu
- Detects projects by looking for common project indicators
- Groups artifacts by project
- Calculates artifact sizes and shows each project's age
- Filters artifacts by age or modification date
- Excludes selected directories by name
- Optionally deletes identified artifacts
- Colorized output

## Supported Languages

CleanSlate identifies common artifacts from:

- **Python**: `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.venv`, `*.pyc`, `*.egg-info`, etc.
- **JavaScript/TypeScript**: `node_modules`, `.next`, `.nuxt`, `.svelte-kit`, `.npm`, `.cache`, etc.
- **Rust**: `/target` (at project root), `.cargo` cache
- **Go**: `.gocache`, `.gomodcache`, `/vendor` (at project root)
- **Ruby**: `.bundle`, `vendor/bundle`
- **Swift/Xcode**: `DerivedData`, `/.build`, `*.xcworkspace/xcuserdata`
- **Java/JVM**: `.gradle`, `.m2`, `/classes`
- **C/C++**: `*.o`, `*.so`, `*.dll`, `CMakeFiles`, etc.
- **Dart/Flutter**: `.dart_tool`, `.pub-cache`
- **Haskell**: `.stack-work`, `dist-newstyle`
- **LaTeX/TeX**: `*.aux`, `*.log`, `*.toc`, `*.synctex.gz`, and other compiler output
- **General**: `tmp`, `logs`, `.idea`, and, in aggressive mode, `.DS_Store` and `Thumbs.db`

## Pattern Syntax

CleanSlate loads its artifact patterns from `artifacts.toml`.

### Pattern Types

1. **Root-level patterns** (with `/` prefix): Only match at project root
   - Example: `/build` matches `<project-root>/build` but does not match `<project-root>/src/build`
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

Root-scoped patterns such as `/build` match only within directories that contain one of these indicators.

## Safety Features

- **Version Control Aware**: Files tracked in Git or Jujutsu are never removed, even if they match artifact patterns
- **VCS Directory Skip**: Skips version control directories during traversal (`.git`, `.jj`, `.svn`, `.hg`, `.bzr`, `_darcs`, `.pijul`, `CVS`, `.fossil`)
- **Nested Repository Protection**: Skips artifact directories that contain version control metadata
- **Fail-Closed VCS Checks**: Keeps files when their tracking status cannot be determined, and reports how many were kept for that reason
- **Pattern-Based Selection**: Individual files must match a pattern before CleanSlate removes them. A matching recreatable directory is handled as one artifact and removed with all its contents when it has no tracked files.
- **Symlink Safety**: Traversal does not follow symlinks. CleanSlate skips a symlink encountered as an artifact, but removing an artifact directory also removes symlink entries inside it.
- **Dry Run Mode**: `--dry-run` previews the deletion set without removing anything; a plain scan is also a preview, since nothing is removed without `--delete`
- **Confirmation Required**: Deleting asks for explicit confirmation, and refuses to run at all when there is no terminal to prompt on unless `--yes` is passed

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

# Skip size calculation for a faster scan
cleanslate --no-sizes

# Show diagnostic details while scanning
cleanslate --verbose

# Exclude directories named vendor
cleanslate --exclude vendor

# Find artifacts older than two weeks
cleanslate --older-than 2w

# Delete artifacts
cleanslate --delete

# Delete without confirming (skip the interactive prompt)
cleanslate --delete --yes
```

## Options

- `[PATHS]...`: Directories to scan (defaults to current directory)
- `-d, --delete`: Delete the found artifacts
- `-y, --yes`: Skip the interactive confirmation prompt and delete all matched artifacts (requires `--delete`)
- `-v, --verbose`: Show detailed information about found artifacts
- `--dry-run`: Preview what would be deleted without deleting; cannot be combined with `--delete`
- `-l, --list`: Show detailed list format instead of table (table is default)
- `--aggressive`: Include small or trivial files such as `.DS_Store`
- `-x, --exclude <DIR>`: Exclude directories by name; may be repeated
- `--older-than <DURATION>`: Select artifacts older than a duration such as `48h`, `15d`, `2w`, or `3m`; plain numbers mean days
- `--modified-before <DATE>`: Select artifacts modified before a date in `YYYY-MM-DD` format
- `--no-sizes`: Skip artifact size calculation for a faster scan (sizes are calculated by default)
- `-h, --help`: Print help
- `-V, --version`: Print version

## Age Filtering

Mixed artifact directories use individual file modification times. Recreatable directories such as `target`, `node_modules`, and `.gomodcache` use the directory's own modification time and are included or excluded as a unit. Changes to a file or nested subdirectory do not necessarily update the top-level directory's modification time.

`--modified-before` interprets its date as midnight in the local time zone. When both time filters are present, an artifact must pass both filters.

## Output Format

By default, CleanSlate displays a table with these columns:

- **Path**: Relative path from scan directory
- **Removable**: Total size of the project's removable artifacts
- **Age**: Age of the project's most recently modified artifact (`today`, `3d`, `2w`, `5mo`, `1y`; `-` when unknown)
- **What**: Artifacts that would be removed

An active time filter also adds a **Too Recent** column. Removable totals over 100 MiB are highlighted, and individual artifacts over 50 MiB are shown in bold.

`--no-sizes` skips size calculation for a faster scan; the table then omits the size columns and ends with an artifact count instead of a total size.

`--list` displays a per-project breakdown grouped by language or tool, with each project's age on its Total line.

If some artifacts were skipped because their version-control status could not be determined, CleanSlate keeps them and reports the count after the report; rerun with `--verbose` to see which paths were affected.

## Interactive Deletion

When `--delete` is used interactively (both stdin and stderr are TTYs), CleanSlate first scans without deleting and then presents a multi-select prompt listing every project, all pre-selected. Each line shows the project's relative path and its removable size (omitted under `--no-sizes`). Press `Space` to toggle selection, `Enter` to confirm, or `Esc` / `Ctrl-C` to cancel.

After the multi-select, CleanSlate prints a one-line summary — `Delete N artifact(s) across M project(s), X GiB?` — and requires an explicit confirmation that defaults to "no", so a bare `Enter` declines. Declining, canceling, or selecting no projects prints "No artifacts deleted." and exits with code 0 without deleting anything.

When stdin or stderr is not a TTY, `--delete` without `--yes` refuses to run rather than deleting silently. Use `--delete --yes` to skip both prompts and delete everything that matched.

## License

MIT License

## Author

Oliver Steele
