# PenHunter

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/release/cc1a2b/PenHunter.svg)](https://github.com/cc1a2b/PenHunter/releases)
[![GitHub stars](https://img.shields.io/github/stars/cc1a2b/PenHunter)](https://github.com/cc1a2b/PenHunter/stargazers)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/cc1a2b/PenHunter/releases)

**🔍 Modular Web Vulnerability Scanner**

*Comprehensive testing for XSS, SQLi, LFI, SSRF, RCE, Open Redirect, and CSRF — built for penetration testers, bug bounty hunters, and security researchers.*

</div>

## 📖 About

**PenHunter** is a powerful, modular web vulnerability scanner written in Go. It provides comprehensive testing for common web vulnerabilities including XSS, SQL Injection, LFI, SSRF, RCE, Open Redirect, and CSRF — with concurrent scanning, advanced detection methods, WAF evasion, and integrations with industry tools like dalfox, sqlmap, and nuclei.

<div align="center">
<img alt="PenHunter Demo" src="https://placehold.co/1600x900/0a0a0a/22c55e?text=PenHunter" width="100%">

*PenHunter — modular vulnerability scanner with interactive and CLI modes.*
</div>

---

## 📑 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Screenshots](#-screenshots)
- [Command Reference](#-command-reference)
- [Advanced Usage](#-advanced-usage)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

---

## ✨ Features

### 🎯 Core Capabilities
- **🔍 Multiple Vulnerability Scanners**: XSS, SQLi, LFI, SSRF, RCE, Open Redirect, CSRF
- **🚀 High Performance**: Concurrent scanning with configurable thread pools
- **🎯 Advanced Detection**: Boolean-based, time-based, error-based detection methods
- **🛡️ WAF Evasion**: Payload mutation, header rotation, TLS fingerprint randomization
- **🔧 External Tool Integration**: dalfox, sqlmap, nuclei, and more
- **📊 Multiple Output Formats**: JSON, HTML, TXT
- **🎨 Interactive CLI**: Menu-driven interface for guided scans
- **🔄 Auto-Update**: Built-in update mechanism via GitHub releases
- **📁 Organized Results**: Automatic directory structure for scan results

### 🧠 Intelligent Detection Engine
> **Differential analysis, boolean/time/error oracles, and payload mutation built in.**

- **🎯 Differential Response Analysis**: Detects subtle behavior changes that confirm vulnerabilities
- **🏢 Multi-Method Coverage**: Boolean-based, time-based, and error-based detection paths per vuln class
- **🧠 Payload Mutation**: Automatic encoding, casing, and obfuscation variants for WAF bypass
- **📊 Confidence Scoring**: Per-finding confidence to filter true positives from noise

### 🌐 Discovery Pipeline
<details>
<summary><strong>Subdomain → URL → endpoint → vulnerability</strong></summary>

PenHunter integrates the best-in-class recon stack:

**Subdomain enumeration:**
- **🔧 subfinder, assetfinder** — passive discovery
- **🍪 amass** (optional) — active + passive

**HTTP probing & URL discovery:**
- **🎭 httpx** — live host probing
- **🌐 urlfinder, katana, gospider** — crawler-based URL collection
- **🧭 gau, gauplus, waybackurls** — wayback machine harvesting

**Endpoint extraction:**
- **🔍 cariddi, getJS** — JS endpoint mining
- **📋 PenHunter native parsing** — built-in JS extractor

**Vulnerability scanning:**
- **🛡️ dalfox, sqlmap, nuclei** — best-in-class engines, orchestrated through PenHunter

</details>

### 🔐 Vulnerability Classes
<details>
<summary><strong>Seven vulnerability classes, comprehensive coverage</strong></summary>

| Class | Detection Methods | Default Engine |
|---|---|---|
| **🔑 XSS** | Reflected, stored, DOM | Native + dalfox |
| **🎫 SQLi** | Boolean, time, error, union | Native + sqlmap |
| **🔥 LFI** | Path traversal, wrapper, log poisoning | Native |
| **📋 SSRF** | Internal, cloud metadata, gopher, file | Native + OOB |
| **🛡️ RCE** | Command injection, template injection | Native + nuclei |
| **🔗 Open Redirect** | Header, parameter, JS-based | Native |
| **📊 CSRF** | Missing token, weak token, predictable | Native |

</details>

### 🌐 HTTP & Networking
<details>
<summary><strong>Production-grade HTTP layer for scaling and stealth</strong></summary>

- **🔧 Custom Headers** (`-H`): Repeatable headers for authenticated scans
- **🍪 Cookie Support** (`-c`): Session cookies for protected resources
- **🎭 User-Agent Rotation**: Built-in UA rotation for evasion
- **⏱️ Rate Limiting**: Configurable request pacing
- **⏰ Timeouts**: Per-request timeout control
- **🔄 Retry Logic**: Exponential backoff on failures
- **🔗 Proxy Support**: Burp Suite and other intercepting proxies
- **🔒 TLS Bypass**: Optional certificate verification skip for testing

</details>

### 📤 Output & Reporting
<details>
<summary><strong>Three formats, organized result hierarchy</strong></summary>

- **🖥️ Console**: Color-coded terminal output with severity highlighting
- **📄 TXT**: Plain text logs for scripting
- **📊 JSON**: Structured output for automation pipelines
- **📈 HTML**: Self-contained reports for stakeholder review

</details>

---

## 📦 Installation

### Go Install (Recommended)
```bash
go install -v github.com/cc1a2b/PenHunter/cmd/penhunter@latest
penhunter --help
```

> Note: `go install` ships only the binary. To get the bundled `config/` (payloads, encoders, user callbacks), clone the repo or use `make install`.

### Build from Source
```bash
git clone https://github.com/cc1a2b/PenHunter.git
cd PenHunter
make build
make install                # installs to $HOME/penhunter/
```

### Add to PATH
```bash
# Linux/macOS
export PATH="$HOME/penhunter/bin:$PATH"

# Or symlink
sudo ln -sf $HOME/penhunter/bin/penhunter /usr/local/bin/penhunter
```

### From Releases
Download the latest release from [GitHub Releases](https://github.com/cc1a2b/PenHunter/releases) and extract to your `$HOME/penhunter/` directory.

### System Requirements
- **Go 1.21+** (for building from source)
- **Linux, macOS, or Windows** (64-bit)
- **External recon tools** (optional but recommended): subfinder, assetfinder, httpx, katana, gau, dalfox, sqlmap, nuclei

---

## 🚀 Quick Start

### Interactive mode
```bash
penhunter
```
Launches the menu where you choose between single-domain or subdomain scanning, vulnerability classes, and engines.

### Single URL scan
```bash
penhunter -u https://example.com -v xss,sqli
```

### Multi-URL scan with JSON output
```bash
penhunter -l urls.txt -v xss -t 50 --json results.json
```

### Update PenHunter
```bash
penhunter --update
```

---

## 💡 Usage Examples

```bash
# Test single URL for XSS + SQLi
penhunter -u https://example.com -v xss,sqli

# Multi-URL scan with custom thread count
penhunter -l urls.txt -v xss -t 50 --json results.json

# Full vulnerability sweep
penhunter -u https://target.com -v xss,sqli,lfi,ssrf,rce,redirect,csrf -t 30

# Stealth scan through Burp Suite
penhunter -u https://target.com -v xss --proxy http://127.0.0.1:8080 -R 1000

# Authenticated scan with cookies and headers
penhunter -u https://target.com -v xss,sqli \
  -c "session=abc123" \
  -H "Authorization: Bearer eyJ..."

# Check installed external tools
penhunter --check-tools

# Check for updates
penhunter --check-update
```

---

## 🖼️ Screenshots

<div align="center">

<img alt="PenHunter — LFI detection" src="https://github.com/user-attachments/assets/03b219d6-2676-439f-ac02-9c9f43e6a767" width="100%">

*LFI vulnerability scan — path traversal detection with confirmed payload.*

<br><br>

<img alt="PenHunter — XSS detection" src="https://github.com/user-attachments/assets/2648f0c8-3c45-4024-b255-c3ea92547f8a" width="100%">

*XSS vulnerability scan — reflected payload confirmed in response.*

</div>

---

## 📋 Command Reference

```
Usage:
  penhunter [flags]

Modes:
  (no args)                       Launch interactive menu
  -u, --url URL                   Test a single URL
  -l, --list FILE                 Test URLs from a file
  -v, --vulns LIST                Comma-separated vulns
                                  (xss, sqli, lfi, ssrf, rce, redirect, csrf)

HTTP & Performance:
  -t, --threads INT               Concurrent threads (default: 10)
  -H, --header "K: V"             Custom HTTP headers (repeatable)
  -c, --cookies STR               Session cookies
  -p, --proxy URL                 HTTP/HTTPS/SOCKS proxy
  -k, --skip-tls                  Skip TLS verification
  -R, --rate-limit MS             Request delay (milliseconds)

Output:
  -o, --output FILE               Output file
  --json FILE                     Structured JSON output
  --html FILE                     HTML report

Maintenance:
  --update                        Update PenHunter to latest
  --check-update                  Check if a new version is available
  --check-tools                   Verify external tools are installed
  -h, --help                      Show help
  -V, --version                   Show version
```

---

## 🔧 Advanced Usage

### Bug Bounty Workflow
```bash
# 1. Subdomain enumeration → URL collection → vuln scan
subfinder -d target.com | httpx | tee live.txt
gau < live.txt | tee urls.txt
penhunter -l urls.txt -v xss,sqli,redirect -t 30 --json findings.json
```

### CI / Continuous Scanning
```bash
penhunter -l production-urls.txt -v xss,sqli \
  --json "scan-$(date +%F).json" \
  -R 2000 \
  --proxy http://internal-proxy:8080
```

### WAF Evasion Scan
```bash
penhunter -u https://target.com -v xss \
  -H "X-Forwarded-For: 1.1.1.1" \
  -H "X-Real-IP: 1.1.1.1" \
  -R 1500
```

---

## 🤝 Contributing

Contributions welcome from the security community.

- **🐛 Report bugs** via [GitHub Issues](https://github.com/cc1a2b/PenHunter/issues)
- **💡 Suggest features** or new vulnerability classes
- **📝 Improve documentation**
- **🔧 Submit pull requests** with new payloads, detectors, or integrations

### Development Setup
```bash
git clone https://github.com/cc1a2b/PenHunter.git
cd PenHunter
go mod tidy
make build
```

---

## 📄 License

PenHunter is released under the **MIT License**. See [LICENSE](https://github.com/cc1a2b/PenHunter/blob/main/LICENSE) for details.

```
Copyright (c) 2024-2026 Hussain Alsharman
Licensed under MIT License — free for commercial and personal use
```

---

## ⭐ Support

If PenHunter helps with your security research:

<div align="center">

**⭐ Star this repo** • **🐦 Follow [@cc1a2b](https://twitter.com/cc1a2b)** • **📢 Share with the security community**

</div>

---

<div align="center">

**🔍 PenHunter — Modular Web Vulnerability Scanner**

*Built with ❤️ by [cc1a2b](https://github.com/cc1a2b) for the security community*

</div>
