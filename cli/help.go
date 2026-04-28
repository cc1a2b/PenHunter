package cli

import (
	"fmt"
	"github.com/cc1a2b/PenHunter/core"
	"github.com/cc1a2b/PenHunter/utils"
)

func ShowHelp() {
	ShowBanner()
	fmt.Printf(`
%sUSAGE:%s
  penhunter [OPTIONS]

%sOPTIONS:%s
  %s-h, --help%s              Show this help message
  %s--version%s               Show version information
  %s--update%s                Update penhunter to the latest version
  %s--check-update%s          Check if a new version is available
  %s--check-tools%s           Check if all required tools are installed
  %s-u, --url%s               Single URL to test
  %s-l, --list%s              File containing list of URLs
  %s-v, --vulns%s             Comma-separated vulnerabilities (xss,sqli,lfi,ssrf,rce,redirect,csrf)
  %s-e, --encoders%s          Comma-separated encoders (url,base64,double,unicode)
  %s-t, --threads%s            Number of concurrent threads (default: 25)
  %s--silent%s                Silent mode (minimal output)
  %s--json%s                  Output results to JSON file
  %s--html%s                  Output results to HTML file
  %s--txt%s                   Output results to text file

%sEXAMPLES:%s
  %sInteractive mode:%s
    penhunter

  %sUpdate penhunter:%s
    penhunter --update

  %sCheck for updates:%s
    penhunter --check-update

  %sCheck installed tools:%s
    penhunter --check-tools

  %sTest single URL:%s
    penhunter -u https://example.com -v xss,sqli

  %sTest URL list:%s
    penhunter -l urls.txt -v xss -t 50 --json results.json

%sINSTALLATION:%s
  Build:
    go build -o bin/penhunter main.go

  Install system-wide:
    sudo mkdir -p /usr/share/penhunter
    sudo cp -r * /usr/share/penhunter
    sudo ln -s /usr/share/penhunter/bin/penhunter /usr/bin/penhunter

%sVERSION:%s
  %s%s%s

%sGITHUB:%s
  https://github.com/cc1a2b/penhunter

%sLICENSE:%s
  MIT License

`,
		utils.Blue, utils.NC,                    // 1-2: USAGE
		utils.Blue, utils.NC,                    // 3-4: OPTIONS
		utils.Green, utils.NC,                   // 5-6: -h, --help
		utils.Green, utils.NC,                   // 7-8: --version
		utils.Green, utils.NC,                   // 9-10: --update
		utils.Green, utils.NC,                   // 11-12: --check-update
		utils.Green, utils.NC,                   // 13-14: --check-tools
		utils.Green, utils.NC,                   // 15-16: -u, --url
		utils.Green, utils.NC,                   // 17-18: -l, --list
		utils.Green, utils.NC,                   // 19-20: -v, --vulns
		utils.Green, utils.NC,                   // 21-22: -e, --encoders
		utils.Green, utils.NC,                   // 23-24: -t, --threads
		utils.Green, utils.NC,                   // 25-26: --silent
		utils.Green, utils.NC,                   // 27-28: --json
		utils.Green, utils.NC,                   // 29-30: --html
		utils.Green, utils.NC,                   // 31-32: --txt
		utils.Yellow, utils.NC,                  // 33-34: EXAMPLES
		utils.Cyan, utils.NC,                    // 35-36: Interactive mode
		utils.Cyan, utils.NC,                    // 37-38: Update penhunter
		utils.Cyan, utils.NC,                    // 39-40: Check for updates
		utils.Cyan, utils.NC,                    // 41-42: Check tools
		utils.Cyan, utils.NC,                    // 43-44: Test single URL
		utils.Cyan, utils.NC,                    // 45-46: Test URL list
		utils.Yellow, utils.NC,                  // 47-48: INSTALLATION
		utils.Yellow, utils.NC,                  // 49-50: VERSION label
		utils.Green, core.CurrentVersion, utils.NC, // 51-53: Version number
		utils.Yellow, utils.NC,                  // 54-55: GITHUB
		utils.Yellow, utils.NC,                  // 56-57: LICENSE
	)
}
