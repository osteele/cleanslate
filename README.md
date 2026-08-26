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
- Offers to delete what it found when run in a terminal, and prints a copyable command otherwise
- Reports artifacts it kept because their version-control status could not be determined
- Colorized output, controllable with `--color` and the `NO_COLOR` convention

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

3. **Wildcard patterns**: Glob matching
   - Example: `*.pyc` matches any file ending in `.pyc`
   - Example: `yarn-*.log` matches `yarn-debug.log`, `yarn-error.log`, etc.
   - Example: `cmake-build-*-debug` matches `cmake-build-x86_64-debug`; several wildcards in one pattern are supported

### Project Root Detection

CleanSlate determines project roots by looking for:
- `Cargo.toml` (Rust)
- `pyproject.toml` (Python)
- `package.json` (JavaScript/Node)
- `go.mod` (Go)
- `Gemfile` (Ruby)
- `pom.xml` (Java/Maven)
- `build.gradle`, `build.gradle.kts` (Java/Gradle)
- `CMakeLists.txt` (C/C++)
- `pubspec.yaml` (Dart/Flutter)
- `Package.swift` (Swift)
- `composer.json` (PHP)
- `mix.exs` (Elixir)
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
# Scan current directory (shows table by default; in a terminal, offers to delete)
cleanslate

# Scan specific directories
cleanslate /path/to/dir1 /path/to/dir2

# Preview what would be deleted without being prompted
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
- `--color <WHEN>`: When to use color in output; `auto` (default), `always`, or `never`
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

Color output is controlled by `--color`:

- `auto` (default) — uses color when stdout is a terminal and the environment allows it. Under `auto`, `NO_COLOR`, `CLICOLOR`, and `CLICOLOR_FORCE` are honored.
- `always` — forces color on, even when output is piped or redirected, and even if `NO_COLOR` is set.
- `never` — forces color off, even if `CLICOLOR_FORCE` is set.

An explicit `--color` value overrides the environment variables. The resulting setting applies to the whole interface: the report, the scan progress indicator, and the interactive prompts.

`--no-sizes` skips size calculation for a faster scan; the table then omits the size columns and ends with an artifact count instead of a total size.

`--list` displays a per-project breakdown grouped by language or tool, with each project's age on its Total line.

If some artifacts were skipped because their version-control status could not be determined, CleanSlate keeps them and reports the count after the report; rerun with `--verbose` to see which paths were affected.

When the output is a terminal, a plain scan ends by offering to delete the same artifacts it just reported. If stdout, stdin, or stderr is redirected (for example, `cleanslate > report.txt`), the scan instead prints the `To delete: cleanslate --delete ...` hint so scripts can capture the report without being interrupted.

## Interactive Deletion

When a plain scan is run in a terminal (stdout, stdin, and stderr are all TTYs) and it found artifacts that are removable — or that an active time filter is holding back — CleanSlate displays the report and then offers to delete the artifacts it found:

```
Delete 12 artifact(s) across 3 project(s), 4.2 GiB — yes/no/choose/filter/quit [y/N/c/f/q]?
```

The size clause is omitted under `--no-sizes`. A single keypress answers it; no `Enter` is needed. The capital `N` marks the default.

- `y` — deletes every project in the plan, exactly as `--delete --yes` does.
- `n`, `Enter`, `Esc`, or `Ctrl-C` — declines. Prints "No artifacts deleted." and exits with code 0 without deleting anything.
- `q` — quits the app immediately, without deleting anything.
- `c` — opens the per-project multi-select, listing every project with all pre-selected. Press `Space` to toggle selection and `Enter` to confirm; `Esc` / `Ctrl-C` cancels and returns to the prompt. Whatever remains selected is deleted immediately with no second confirmation.
- `f` — changes the time filter. Enter a duration (`15d`, `2w`, `3m`, `48h`), a date (`YYYY-MM-DD`), or an empty line to remove the limit. CleanSlate rescans with the new cutoff and redisplays the report; a later deletion acts on the refreshed plan.

Any other key is ignored and the prompt keeps waiting.

If stdout, stdin, or stderr is redirected (for example, `cleanslate > report.txt`), a plain scan does not prompt; it prints the `To delete: cleanslate --delete ...` hint instead so the report remains scriptable. Use `--dry-run` to preview the deletion set without being prompted.

When `--delete` is used without `--yes`, CleanSlate still requires an interactive session (both stdin and stderr are TTYs) and refuses to run otherwise, rather than deleting silently. Use `--delete --yes` to skip the prompt and delete everything that matched.

## Exit Codes

- `0` — the run completed, whether or not artifacts were found, and whether or not you chose to delete them
- `1` — deletion was refused for want of a confirmation prompt, or one or more artifacts could not be removed
- `2` — the command line was invalid

Finding artifacts is not an error, so a scan that reports several gigabytes still exits `0`. To act on the result in a script, parse the report or use `--delete --yes`.

## License

MIT License

## Author

Oliver Steele
