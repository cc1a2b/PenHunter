# PenHunter 🔍

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue.svg)](https://github.com/cc1a2b/penhunter/releases)

**PenHunter** is a powerful, modular web vulnerability scanner written in Go. It provides comprehensive testing for common web vulnerabilities including XSS, SQL Injection, LFI, SSRF, RCE, Open Redirect, and CSRF.

## ✨ Features

- 🔍 **Multiple Vulnerability Scanners**: XSS, SQLi, LFI, SSRF, RCE, Open Redirect, CSRF
- 🚀 **High Performance**: Concurrent scanning with configurable thread pools
- 🎯 **Advanced Detection**: Boolean-based, time-based, error-based detection methods
- 🛡️ **WAF Evasion**: Payload mutation, header rotation, TLS fingerprint randomization
- 🔧 **External Tool Integration**: Supports dalfox, sqlmap, nuclei, and more
- 📊 **Multiple Output Formats**: JSON, HTML, TXT
- 🎨 **Interactive CLI**: Menu-driven interface matching the original shell script
- 🔄 **Auto-Update**: Built-in update mechanism via GitHub releases
- 📁 **Organized Results**: Automatic directory structure for scan results

## 📋 Requirements

- Go 1.21 or higher
- External tools (optional but recommended):
  - `subfinder`, `assetfinder` - Subdomain enumeration
  - `httpx` - HTTP probing
  - `urlfinder`, `katana`, `gospider` - URL discovery
  - `gau`, `gauplus`, `waybackurls` - Wayback machine URLs
  - `cariddi`, `getJS` - Endpoint discovery
  - `dalfox`, `sqlmap`, `nuclei` - Vulnerability scanning

## 🚀 Installation

### Quick Install (Go)

```bash
go install -v github.com/cc1a2b/PenHunter/cmd/penhunter@latest
```

The binary lands in `$(go env GOPATH)/bin/penhunter` — make sure that directory is on your `PATH`.

> Note: `go install` only ships the binary. To get the bundled `config/` (payloads, encoders, user callbacks), clone the repo or use `make install`.

### From Source

```bash
# Clone the repository
git clone https://github.com/cc1a2b/PenHunter.git
cd PenHunter

# Build
make build

# Install to user home directory
make install
# This installs to $HOME/penhunter/
```

### Installation Paths

- **Linux/macOS**: `$HOME/penhunter/`
- **Windows**: `%USERPROFILE%\penhunter\`

After installation, add to your PATH:
```bash
export PATH="$HOME/penhunter/bin:$PATH"
```

Or create a symlink:
```bash
sudo ln -sf $HOME/penhunter/bin/penhunter /usr/local/bin/penhunter
```

### From Releases

Download the latest release from [GitHub Releases](https://github.com/cc1a2b/penhunter/releases) and extract to your `$HOME/penhunter/` directory.

## 📖 Usage

### Interactive Mode

```bash
penhunter
```

This launches the interactive menu system where you can:
1. Choose between single domain or subdomain scanning
2. Select vulnerability types to test
3. Choose between native scanner or external tools

### Command Line Mode

```bash
# Test single URL
penhunter -u https://example.com -v xss,sqli

# Test URL list
penhunter -l urls.txt -v xss -t 50 --json results.json

# Update penhunter
penhunter --update

# Check for updates
penhunter --check-update

# Check installed tools
penhunter --check-tools
```

### Options

```
-h, --help              Show help message
-v, --version           Show version information
--update                Update penhunter to the latest version
--check-update          Check if a new version is available
--check-tools           Check if all required tools are installed
-u, --url               Single URL to test
-l, --list              File containing list of URLs
-v, --vulns             Comma-separated vulnerabilities (xss,sqli,lfi,ssrf,rce,redirect,csrf)
-e, --encoders          Comma-separated encoders (url,base64,double,unicode)
-t, --threads           Number of concurrent threads (default: 25)
--silent                Silent mode (minimal output)
--json                  Output results to JSON file
--html                  Output results to HTML file
--txt                   Output results to text file
```

## 📁 Directory Structure

```
penhunter/
├── bin/                 # Compiled binary
├── config/              # Configuration files
│   ├── user_config.yaml # YOUR callback URLs (configure this!)
│   ├── payloads.yaml
│   ├── encoders.yaml
│   └── defaults.yaml
├── core/                # Core engine
│   ├── engine.go
│   ├── http.go
│   ├── logger.go
│   ├── runner.go
│   ├── tools.go
│   └── updater.go
├── scanners/            # Vulnerability scanners
│   ├── xss.go
│   ├── sqli.go
│   ├── lfi.go
│   ├── ssrf.go
│   ├── rce.go
│   ├── redirect.go
│   └── csrf.go
├── encoders/            # Payload encoders
│   ├── url.go
│   ├── base64.go
│   ├── double.go
│   └── unicode.go
├── cli/                 # CLI interface
│   ├── flags.go
│   ├── banner.go
│   └── help.go
├── output/              # Output formatters
│   ├── json.go
│   ├── txt.go
│   └── html.go
├── utils/               # Utilities
│   ├── colors.go
│   ├── regex.go
│   └── random.go
├── types/               # Type definitions
│   └── finding.go
├── cmd/penhunter/main.go
├── go.mod
├── Makefile
└── README.md
```

## 🔧 Configuration

### User Configuration (IMPORTANT)

Before using blind XSS or callback-based testing, configure your callback URLs in:
```
$HOME/penhunter/config/user_config.yaml
```

Example configuration:
```yaml
# XSS Callback URL - Used for blind XSS testing
xss_callback: "https://xss.report/c/YOUR_ID"

# Redirect Test Domain - Used for open redirect testing
redirect_domain: "evil.com"

# SSRF Callback URL - Used for blind SSRF testing
ssrf_callback: "https://YOUR_BURP_COLLABORATOR.burpcollaborator.net"

# Out-of-Band (OOB) Server
oob_server: "https://YOUR_OOB_SERVER"
```

You can use services like:
- [xss.report](https://xss.report)
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
- [Interactsh](https://github.com/projectdiscovery/interactsh)

### Results Directory

Results are saved to `$HOME/penhunter/`:
- `penhunter/one/YYYY-MM/domain/` - Single domain scans
- `penhunter/subdomains/YYYY-MM/domain/` - Subdomain scans

Each scan creates:
- `domain_urls_targets.txt` - Collected URLs
- `all_subdomains.txt` - All discovered subdomains
- `subs.txt` - Live subdomains
- Scanner-specific output files

## Example

![lfi](https://github.com/user-attachments/assets/03b219d6-2676-439f-ac02-9c9f43e6a767)
![xss](https://github.com/user-attachments/assets/2648f0c8-3c45-4024-b255-c3ea92547f8a)

## 🛠️ Development

```bash
# Build
make build

# Install
make install

# Clean
make clean
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.

## 🙏 Acknowledgments

- Created by [cc1a2b](https://github.com/cc1a2b)
- Inspired by the original `penhunter.sh` script
- Built with Go and love ❤️

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/cc1a2b/penhunter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/cc1a2b/penhunter/discussions)

---

**Made with ❤️ by cc1a2b**
