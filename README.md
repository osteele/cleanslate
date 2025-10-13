# CleanSlate

A command-line tool that recursively examines directories to find and optionally clean build artifacts and cache files from various programming languages.

## Features

- Scans directories recursively to identify build artifacts and caches
- Respects `.gitignore` patterns
- Detects projects by looking for common project indicators
- Groups artifacts by project
- Calculates total size of artifacts
- Optionally deletes identified artifacts
- Colorized output

## Supported Languages

CleanSlate identifies common artifacts from:

- Python (`__pycache__`, `.pytest_cache`, etc.)
- JavaScript/TypeScript (`node_modules`, `.next`, `dist`, etc.)
- Rust (`target`, etc.)
- Go (`bin`, `pkg`, `vendor`, etc.)
- General artifacts (`.DS_Store`, `Thumbs.db`, etc.)

## Installation

```bash
cargo install cleanslate
```

Or build from source:

```bash
git clone https://github.com/osteele/cleanslate.git
cd cleanslate
cargo install --path .
```

## Usage

```bash
# Scan current directory
cleanslate

# Scan specific directories
cleanslate /path/to/dir1 /path/to/dir2

# Show verbose output
cleanslate -v

# Delete artifacts
cleanslate --delete
```

## Options

- `[PATHS]...`: Directories to scan (defaults to current directory)
- `-d, --delete`: Delete the found artifacts
- `-v, --verbose`: Show detailed information about found artifacts
- `-h, --help`: Print help
- `-V, --version`: Print version

## License

MIT License

## Author

Oliver Steele