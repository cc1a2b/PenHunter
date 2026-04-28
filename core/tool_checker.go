package core

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"penhunter/utils"
)

// Tool represents an external tool
type Tool struct {
	Name        string
	Description string
	Required    bool
	Category    string
}

// GetAllTools returns all tools used by PenHunter
func GetAllTools() []Tool {
	return []Tool{
		// Subdomain Enumeration Tools
		{Name: "subfinder", Description: "Fast subdomain discovery tool", Required: true, Category: "Subdomain Enumeration"},
		{Name: "assetfinder", Description: "Find domains and subdomains", Required: true, Category: "Subdomain Enumeration"},
		{Name: "httpx", Description: "Fast HTTP toolkit", Required: true, Category: "Subdomain Enumeration"},

		// URL Discovery Tools
		{Name: "urlfinder", Description: "Passive URL discovery", Required: true, Category: "URL Discovery"},
		{Name: "katana", Description: "Web crawling framework", Required: true, Category: "URL Discovery"},
		{Name: "gau", Description: "Fetch known URLs from AlienVault's Open Threat Exchange, Wayback Machine, and Common Crawl", Required: true, Category: "URL Discovery"},
		{Name: "gauplus", Description: "Enhanced version of gau", Required: false, Category: "URL Discovery"},
		{Name: "hakrawler", Description: "Web crawler for gathering URLs", Required: false, Category: "URL Discovery"},
		{Name: "waybackurls", Description: "Fetch URLs from Wayback Machine", Required: false, Category: "URL Discovery"},
		{Name: "gospider", Description: "Fast web spider", Required: true, Category: "URL Discovery"},
		{Name: "cariddi", Description: "Web crawler with automatic secret detection", Required: false, Category: "URL Discovery"},
		{Name: "getJS", Description: "Extract JavaScript files from URLs", Required: false, Category: "URL Discovery"},

		// Utility Tools
		{Name: "qsreplace", Description: "Replace query string values", Required: true, Category: "Utilities"},
		{Name: "anew", Description: "Append new lines to files", Required: true, Category: "Utilities"},
		{Name: "tmux", Description: "Terminal multiplexer", Required: true, Category: "Utilities"},
		{Name: "gf", Description: "Grep patterns for security research", Required: true, Category: "Utilities"},
		{Name: "freq", Description: "Frequency analysis tool", Required: false, Category: "Utilities"},
		{Name: "curl", Description: "Transfer data from or to a server", Required: true, Category: "Utilities"},

		// XSS Scanners
		{Name: "dalfox", Description: "Powerful XSS scanner", Required: false, Category: "XSS Scanners"},
		{Name: "bxss", Description: "Blind XSS scanner", Required: false, Category: "XSS Scanners"},
		{Name: "xsstrike", Description: "Advanced XSS detection suite", Required: false, Category: "XSS Scanners"},

		// SQL Injection Scanners
		{Name: "sqlmap", Description: "Automatic SQL injection tool", Required: false, Category: "SQLi Scanners"},
		{Name: "ghauri", Description: "Advanced SQL injection scanner", Required: false, Category: "SQLi Scanners"},

		// Other Vulnerability Scanners
		{Name: "nuclei", Description: "Fast vulnerability scanner", Required: false, Category: "Vulnerability Scanners"},
		{Name: "redirect-checker", Description: "Open redirect vulnerability checker", Required: false, Category: "Vulnerability Scanners"},
		{Name: "ssrf-checker", Description: "SSRF vulnerability checker", Required: false, Category: "Vulnerability Scanners"},
	}
}

// CheckTool checks if a tool is installed
func CheckTool(toolName string) bool {
	_, err := exec.LookPath(toolName)
	return err == nil
}

// CheckAllTools checks all tools and returns results
func CheckAllTools() (map[string]bool, []string, []string) {
	tools := GetAllTools()
	results := make(map[string]bool)
	var missing []string
	var missingRequired []string

	for _, tool := range tools {
		installed := CheckTool(tool.Name)
		results[tool.Name] = installed

		if !installed {
			missing = append(missing, tool.Name)
			if tool.Required {
				missingRequired = append(missingRequired, tool.Name)
			}
		}
	}

	return results, missing, missingRequired
}

// PrintToolStatus prints the status of all tools
func PrintToolStatus() {
	tools := GetAllTools()
	results, _, missingRequired := CheckAllTools()

	// Group tools by category
	categories := make(map[string][]Tool)
	for _, tool := range tools {
		categories[tool.Category] = append(categories[tool.Category], tool)
	}

	// Sort categories
	var categoryNames []string
	for category := range categories {
		categoryNames = append(categoryNames, category)
	}
	sort.Strings(categoryNames)

	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════╗%s\n", utils.Cyan, utils.NC)
	fmt.Printf("%s║              PenHunter Tool Installation Status                 ║%s\n", utils.Cyan, utils.NC)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════╝%s\n", utils.Cyan, utils.NC)
	fmt.Println()

	for _, category := range categoryNames {
		fmt.Printf("%s%s:%s\n", utils.Yellow, category, utils.NC)
		fmt.Println(strings.Repeat("─", 70))

		for _, tool := range categories[category] {
			status := results[tool.Name]
			statusStr := ""
			colorStart := ""
			requiredTag := ""

			if status {
				statusStr = "✓ Installed"
				colorStart = utils.Green
			} else {
				statusStr = "✗ Not Installed"
				colorStart = utils.Red
			}

			if tool.Required {
				requiredTag = fmt.Sprintf("%s[REQUIRED]%s", utils.Red, utils.NC)
			} else {
				requiredTag = fmt.Sprintf("%s[OPTIONAL]%s", utils.Gray, utils.NC)
			}

			fmt.Printf("  %s%-20s%s %s%-15s%s %s\n",
				utils.Blue, tool.Name, utils.NC,
				colorStart, statusStr, utils.NC,
				requiredTag)
		}
		fmt.Println()
	}

	// Summary
	installed := 0
	for _, status := range results {
		if status {
			installed++
		}
	}

	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════╗%s\n", utils.Cyan, utils.NC)
	fmt.Printf("%s║                           Summary                                ║%s\n", utils.Cyan, utils.NC)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════╝%s\n", utils.Cyan, utils.NC)
	fmt.Printf("  Total Tools: %d\n", len(tools))
	fmt.Printf("  %sInstalled: %d%s\n", utils.Green, installed, utils.NC)
	fmt.Printf("  %sNot Installed: %d%s\n", utils.Red, len(tools)-installed, utils.NC)

	if len(missingRequired) > 0 {
		fmt.Printf("\n%s⚠ WARNING: Missing required tools:%s\n", utils.Red, utils.NC)
		for _, tool := range missingRequired {
			fmt.Printf("  - %s\n", tool)
		}
		fmt.Printf("\n%sPenHunter may not function correctly without these tools.%s\n", utils.Yellow, utils.NC)
	} else {
		fmt.Printf("\n%s✓ All required tools are installed!%s\n", utils.Green, utils.NC)
	}
}

// QuickCheck performs a quick check of required tools only
func QuickCheck() error {
	_, _, missingRequired := CheckAllTools()

	if len(missingRequired) > 0 {
		return fmt.Errorf("missing required tools: %s", strings.Join(missingRequired, ", "))
	}

	return nil
}

// GetInstallationInstructions returns installation instructions for a tool
func GetInstallationInstructions(toolName string) string {
	instructions := map[string]string{
		"subfinder":        "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
		"assetfinder":      "go install github.com/tomnomnom/assetfinder@latest",
		"httpx":            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
		"urlfinder":        "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
		"katana":           "go install github.com/projectdiscovery/katana/cmd/katana@latest",
		"gau":              "go install github.com/lc/gau/v2/cmd/gau@latest",
		"gauplus":          "go install github.com/bp0lr/gauplus@latest",
		"hakrawler":        "go install github.com/hakluke/hakrawler@latest",
		"waybackurls":      "go install github.com/tomnomnom/waybackurls@latest",
		"gospider":         "go install github.com/jaeles-project/gospider@latest",
		"cariddi":          "go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest",
		"getJS":            "go install github.com/003random/getJS@latest",
		"qsreplace":        "go install github.com/tomnomnom/qsreplace@latest",
		"anew":             "go install github.com/tomnomnom/anew@latest",
		"gf":               "go install github.com/tomnomnom/gf@latest",
		"freq":             "go install github.com/takshal/freq@latest",
		"dalfox":           "go install github.com/hahwul/dalfox/v2@latest",
		"bxss":             "go install github.com/ethicalhackingplayground/bxss@latest",
		"xsstrike":         "pip install xsstrike",
		"sqlmap":           "apt install sqlmap OR pip install sqlmap",
		"ghauri":           "pip install ghauri",
		"nuclei":           "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
		"redirect-checker": "go install github.com/dwisiswant0/redirect-checker@latest",
		"ssrf-checker":     "go install github.com/dwisiswant0/ssrf-checker@latest",
		"tmux":             "apt install tmux OR brew install tmux",
		"curl":             "apt install curl OR brew install curl",
	}

	if inst, ok := instructions[toolName]; ok {
		return inst
	}
	return "Installation instructions not available. Please check the tool's official repository."
}

// PrintInstallationInstructions prints installation instructions for missing tools
func PrintInstallationInstructions() {
	_, missing, _ := CheckAllTools()

	if len(missing) == 0 {
		fmt.Printf("%s✓ All tools are installed!%s\n", utils.Green, utils.NC)
		return
	}

	fmt.Printf("%s╔══════════════════════════════════════════════════════════════════╗%s\n", utils.Cyan, utils.NC)
	fmt.Printf("%s║                   Installation Instructions                      ║%s\n", utils.Cyan, utils.NC)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════════╝%s\n", utils.Cyan, utils.NC)
	fmt.Println()

	for _, tool := range missing {
		fmt.Printf("%s%s:%s\n", utils.Yellow, tool, utils.NC)
		fmt.Printf("  %s\n\n", GetInstallationInstructions(tool))
	}
}
