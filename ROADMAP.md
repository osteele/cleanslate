# CleanSlate Roadmap

This document outlines planned improvements and future features for CleanSlate.

## Version Control Safety Enhancements

### Completed ✅
- Skip files tracked in Git
- Skip files tracked in Jujutsu (jj)

### Future Improvements
- Cache VCS tracking status for performance
- Add `--ignore-vcs` flag to bypass VCS checks (for advanced users)
- Better handling of submodules and nested repositories

## Monorepo Support

### Current Behavior
- `node_modules` matches anywhere in the directory tree (supports basic monorepo use)

### Planned Improvements
- **Smart monorepo detection**: Identify monorepo patterns (workspace configs, lerna.json, pnpm-workspace.yaml, etc.)
- **Workspace-aware scanning**: Understand workspace roots vs package roots
- **Configurable depth limits**: Allow users to specify how deep to scan in monorepos
- **Parallel processing**: Speed up scanning of large monorepos with parallel workers

## Pattern System Enhancements

### Future Additions
- **Configurable patterns**: Allow users to add custom patterns via `.cleanslate.toml` in project root
- **Pattern priorities**: Let users override or disable specific patterns
- **Language-specific configuration**: Enable/disable entire language pattern sets
- **Size thresholds**: Optionally skip artifacts below a certain size

## Aggressive Cleanup Mode

### Planned Feature: `--aggressive` Flag

Safely remove additional files that might be useful for recovery:

- `.git/logs` (reflog history - useful for undoing mistakes)
- `.git/lfs/tmp` (LFS temporary cache)
- Build caches that are slow to regenerate
- Download caches (Cargo registry, pip cache, etc.)

**Important**: These removals should be opt-in only since they remove safety/recovery options.

### Subcommands for Specific Cleanups

```bash
cleanslate clean-git-lfs    # Clean only Git LFS temp files
cleanslate clean-logs       # Clean only log files
cleanslate clean-caches     # Clean only cache directories (preserve build outputs)
```

## Performance Improvements

### Current Performance Characteristics
- Single-threaded directory traversal
- Synchronous VCS checks (git/jj commands)

### Planned Optimizations
- **Parallel directory scanning**: Use rayon for concurrent traversal
- **Batch VCS checks**: Check multiple files in one git/jj command
- **Smart caching**: Cache project root detection results
- **Early termination**: Skip scanning inside large artifact directories
- **Progress indicators**: Show progress for long-running scans

## User Experience

### Interactive Mode
- Prompt before deleting each category of artifacts
- Show examples of what will be deleted
- Allow selective deletion by language or artifact type

### Reporting
- Export reports in JSON/CSV format
- Generate size trend reports over time
- Integration with CI/CD for artifact monitoring

### Configuration
- Support `.cleanslate.toml` project configuration
- Global configuration in `~/.config/cleanslate/config.toml`
- Per-language enable/disable flags

## Platform-Specific Features

### Windows
- Better handling of locked files
- Integration with Windows filesystem APIs for faster scanning

### macOS
- Spotlight metadata cleanup
- Xcode-specific optimizations

### Linux
- Better handling of case-sensitive filesystems
- Integration with package managers (apt cache, etc.)

## Safety and Recovery

### Planned Features
- **Backup mode**: Move files to trash/recycle bin instead of deleting
- **Undo support**: Keep a log of deletions with option to restore
- **Dry-run improvements**: Better preview of what will be deleted with file counts
- **Whitelist support**: Never delete specific files even if they match patterns

## Integration

### Version Control Systems
- Deeper Git integration (git worktree awareness)
- Mercurial support
- Fossil support

### Build Tools
- Integration with build system clean commands
- Detect and use native clean commands when available

### IDE Integration
- VS Code extension
- IntelliJ plugin
- CLI server mode for editor integration

## Testing

### Current Coverage
- Basic pattern matching tests
- Project root detection tests

### Planned Improvements
- Integration tests with real project structures
- Performance benchmarks
- Cross-platform testing automation
- Regression test suite with real-world repositories

## Documentation

### Planned Additions
- Detailed pattern reference guide
- Migration guides (from other cleanup tools)
- Video tutorials
- FAQ section
- Architecture documentation

## Community Features

### Future Plans
- Community pattern repository
- Pattern sharing system
- Language-specific pattern packages
- User-submitted patterns and reviews

## Long-term Vision

### CleanSlate 2.0 Ideas
- **AI-powered detection**: Use ML to identify build artifacts by content
- **Cloud integration**: Sync cleanup settings across machines
- **Team features**: Shared cleanup policies for development teams
- **Analytics**: Track disk space savings over time
- **Recommendations**: Suggest cleanup schedules based on usage patterns

---

## Contributing

Have ideas for CleanSlate? We'd love to hear them!

- Open an issue on GitHub for feature requests
- Submit PRs for implementation
- Discuss on GitHub Discussions

## Priority Order

Current development priorities:

1. **High Priority**
   - Monorepo detection and handling
   - Performance optimization for large codebases
   - Better test coverage

2. **Medium Priority**
   - Aggressive cleanup mode
   - Interactive mode
   - Configuration files support

3. **Low Priority**
   - Platform-specific optimizations
   - Advanced reporting
   - IDE integrations

---

*Last updated: 2025-01-03*
