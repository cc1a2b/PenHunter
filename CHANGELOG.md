# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-XX

### Added
- Initial release of PenHunter Go implementation
- Interactive CLI menu system matching original shell script
- 7 vulnerability scanners: XSS, SQLi, LFI, SSRF, RCE, Open Redirect, CSRF
- Advanced detection methods (error-based, time-based, boolean-based)
- Payload mutation and encoding (URL, Base64, Double, Unicode)
- Concurrent scanning with thread pools
- Per-host rate limiting
- WAF evasion techniques
- External tool integration (dalfox, sqlmap, nuclei, etc.)
- Multiple output formats (JSON, HTML, TXT)
- Auto-update mechanism via GitHub releases
- Subdomain enumeration support
- URL collection from multiple sources
- Organized directory structure for results
- Color-coded output matching original script
- System-wide installation support

### Features
- Interactive menu-driven interface
- Command-line flag support
- Automatic result organization in `/home/$USER/penhunter/`
- Support for existing scan directories
- tmux session integration for external tools
- Comprehensive help system
- Version checking and update functionality

### Technical
- Modular architecture
- Type-safe interfaces
- Comprehensive error handling
- Race condition fixes
- Memory-efficient scanning
- Cross-platform support (Linux, macOS, Windows)

[0.1.0]: https://github.com/cc1a2b/penhunter/releases/tag/v0.1.0

