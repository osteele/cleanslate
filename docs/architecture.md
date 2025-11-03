# CleanSlate Architecture

## Overview

CleanSlate is a **selective** artifact cleaner that removes build artifacts and caches based on two criteria:
1. File matches an artifact pattern (from `artifacts.toml`)
2. File is not tracked in version control

**This is NOT the same as `git clean`**, which removes all untracked files regardless of whether they're artifacts.

### Why Not Just Use `git clean`?

`git clean` removes **all** untracked files, including:
- New source files you're working on
- Configuration files you haven't committed yet
- Any other untracked content

CleanSlate is **surgical**: it only removes things that match known artifact patterns (like `node_modules`, `*.pyc`, `target/`, etc.), leaving your untracked work files alone.

## Layered Removal Strategy

CleanSlate uses a multi-layer decision process for whether to remove a file or directory:

### Layer 1: Pattern Matching (artifacts.toml)
- Does the file/directory path match any pattern in `artifacts.toml`?
- Patterns include: `node_modules`, `*.pyc`, `target`, `__pycache__`, etc.
- If NO match → keep the file (even if untracked)
- If match → proceed to Layer 2

### Layer 2: VCS Tracking Status
- Is the file tracked in version control (git/jj)?
- Checked via `git ls-files` or `jj file list` (NOT gitignore!)
- If tracked → keep the file (overrides pattern match)
- If untracked → proceed to Layer 3

### Layer 3: Directory Category
Based on directory type, use different performance optimizations:
- **VCS Internals**: Never traverse (`.git`, `.jj`, etc.)
- **Recreatable Dirs**: Spot-check for any tracked files (`node_modules`, `.venv`, etc.)
- **Other Dirs**: Batch-check all files

### Example Decision Tree

```
src/app.js (untracked)
  → Layer 1: No pattern match
  → Result: KEEP (not an artifact)

node_modules/lib.js (tracked in git)
  → Layer 1: Matches "node_modules" pattern ✓
  → Layer 2: Tracked in git
  → Result: KEEP (tracking overrides pattern)

node_modules/new-lib.js (untracked)
  → Layer 1: Matches "node_modules" pattern ✓
  → Layer 2: Not tracked in git ✓
  → Result: REMOVE (pattern + untracked)

.git/config
  → Layer 1: Matches VCS internals
  → Layer 3: Category 1 (VCS internal)
  → Result: SKIP (never remove)
```

## Directory Removal Strategy

### Three Directory Categories

#### Category 1: VCS Internals (Never Remove, Skip Traversal)
**Directories:** `.git`, `.jj`, `.svn`, `.hg`, `.bzr`, `_darcs`, `.pijul`, `CVS`, `.fossil`

**Strategy:** Skip during traversal entirely. These are never removable.

**Code location:** `src/main.rs:497-510`, `src/main.rs:581`

**Why:** These contain version control metadata and must never be touched.

#### Category 2: Recreatable Directories (Spot-Check, Remove if Untracked)
**Directories:** `node_modules`, `.venv`, `venv`, `env`, `target`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.gradle`, `.m2`, `vendor/bundle`, `.dart_tool`, etc.

**Strategy:** These can be recreated from manifest files (package.json, requirements.txt, Cargo.toml, etc.)
- Check if directory contains ANY tracked files (single VCS call with early exit)
- If yes → skip directory entirely (unusual but valid case where someone committed node_modules)
- If no → remove entire directory without traversing contents

**Performance:** 1 VCS call vs N calls for N files (10,000x+ speedup for large directories)

**Code location:** `src/main.rs:~60` (directory list), `src/main.rs:~600-663` (handling logic)

**Why this works:** These directories are conventionally never tracked, so the spot-check almost always finds no tracked files and we can skip the expensive traversal.

#### Category 3: Other Directories (Batch-Check Contents)
**Definition:** Any directory not in categories 1 or 2.

**Strategy:**
- Batch-check all files in directory with single VCS call
- Remove untracked files that match artifact patterns
- Cleanup empty directories recursively

**Performance:** 1 VCS call per directory vs N calls for N files

**Code location:** `src/main.rs:~600-700`

**Why this is needed:** Custom project directories may contain a mix of artifacts and source files, so we need file-level granularity.

## Critical Semantic Rule: VCS Tracking vs Gitignore

### The Core Logic

**Files are removed when BOTH conditions are true:**
1. File matches an artifact pattern (defined in `artifacts.toml`)
2. File is NOT tracked in version control

This is checked in the layered approach described above.

### Why This Matters

Git and Jujutsu **only track files, not directories**:
- An empty directory cannot be committed
- To check if a directory is "tracked", we check if it contains any tracked files

### Common Pitfall: Don't Use Gitignore for Removal!

**Gitignore ≠ Untracked**

A file's gitignore status is NOT the same as its tracking status:
- **A file can be tracked even if it's in `.gitignore`** (if it was added before the ignore rule was created)
- A file can be untracked but NOT in `.gitignore`
- Gitignore only affects whether NEW files get auto-tracked

**Why this is critical:**
If someone committed `node_modules/` before adding it to `.gitignore`, those files are TRACKED. Using gitignore would incorrectly mark them for removal, potentially deleting important tracked files.

**Examples:**
```
# node_modules/lib.js is tracked in git (someone committed it)
→ KEEP (Layer 2: tracking overrides pattern)

# node_modules/new.js is untracked
→ REMOVE (Layer 1 + Layer 2: pattern + untracked)

# src/app.js is untracked
→ KEEP (Layer 1: doesn't match artifact pattern)
```

### The Role of the `ignore` Crate

The `ignore` crate (used via `WalkBuilder`) is **ONLY for traversal optimization**, NOT for removal decisions.

It helps us skip directories during traversal (respects `.gitignore`), but we **must** query VCS tracking status via `git ls-files` or `jj file list` to make removal decisions.

**Why we use it:** If `.gitignore` says to ignore `node_modules`, the `WalkBuilder` won't traverse into it, saving time. But this is just an optimization - the removal decision still requires checking VCS tracking.

## VCS Checking Strategy

### Why Spot-Check Works for Category 2

Since git/jj only track files, checking if a directory is "untracked" means:
```bash
# If this returns nothing, directory has no tracked files
git ls-files node_modules | head -1
jj file list 'node_modules' | head -1
```

This avoids traversing 10,000+ files when we only need a yes/no answer.

**Key insight:** For conventionally-untracked directories like `node_modules`, this check almost always returns nothing immediately, giving us a 10,000x speedup.

### Batch Checking for Category 3

For other directories, we need file-level granularity:
```bash
# Get all tracked files in one call
git ls-files some-directory
jj file list --ignore-working-copy 'glob:"some-directory/**"'
```

Then check each file against this cached set (O(1) lookup).

### VCS Detection Priority

When both `.jj` and `.git` are present:
1. **Prefer Jujutsu** (`.jj` takes precedence)
2. Use `jj file list --ignore-working-copy` (faster, skips snapshot)
3. Fall back to Git only if `.jj` not found

**Why prefer jj:** Per user configuration in `.claude/CLAUDE.md`, when both exist, use jj.

## Performance Impact

### Before Optimization
- **O(N) subprocess calls** where N = total files in artifact directories
- Example: `node_modules` with 10,000 files = 10,000 subprocess calls
- Result: **Hangs for minutes or hours**

### After Optimization
- **Category 1:** O(0) - skipped during traversal
- **Category 2:** O(1) subprocess call per directory (spot-check with early exit)
- **Category 3:** O(1) subprocess call per directory (batch check)
- Example: `node_modules` with 10,000 files = 1 subprocess call
- Result: **Completes in seconds**

### Expected Speedup
- Large projects: **100-10,000x speedup**
- Typical project: **10-100x speedup**

## Empty Directory Cleanup

After removing files, directories may become empty. The cleanup pass:
1. Collects all parent directories of removed files/directories
2. Sorts directories by depth (deepest first)
3. Checks if directory is empty OR only contains `.DS_Store`/`Thumbs.db`
4. Removes empty directories
5. Recursively removes parent directories that become empty

**Why this matters:** Removing files from `src/build/output/file.o` should also remove the empty `output/` and `build/` directories if they become empty.

**Code location:** `src/main.rs:~720-795`
