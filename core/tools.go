package core

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"penhunter/utils"
)

// NormalizeURL normalizes a URL to prevent duplicates with different formats
func NormalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	// Parse URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Normalize scheme
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)

	// Normalize host (lowercase)
	parsed.Host = strings.ToLower(parsed.Host)

	// Remove default ports
	host := parsed.Host
	if strings.HasSuffix(host, ":80") && parsed.Scheme == "http" {
		parsed.Host = strings.TrimSuffix(host, ":80")
	}
	if strings.HasSuffix(host, ":443") && parsed.Scheme == "https" {
		parsed.Host = strings.TrimSuffix(host, ":443")
	}

	// Normalize path - remove trailing slash if not root
	if parsed.Path != "/" && strings.HasSuffix(parsed.Path, "/") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}

	// Sort query parameters for consistent comparison
	if parsed.RawQuery != "" {
		query := parsed.Query()
		var keys []string
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var parts []string
		for _, k := range keys {
			for _, v := range query[k] {
				if v == "" {
					parts = append(parts, url.QueryEscape(k)+"=")
				} else {
					parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
				}
			}
		}
		parsed.RawQuery = strings.Join(parts, "&")
	}

	// Remove fragment
	parsed.Fragment = ""

	return parsed.String()
}

// NormalizeDomain normalizes a domain name
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.Split(domain, "/")[0]
	domain = strings.Split(domain, ":")[0]
	return domain
}

// RunCommand executes a shell command and returns output
func RunCommand(name string, args ...string) ([]string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// RunCommandWithInput runs command with stdin input
func RunCommandWithInput(input string, name string, args ...string) ([]string, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// FilterURLs filters URLs using the same patterns as the shell script
func FilterURLs(urls []string, domain string) []string {
	var filtered []string
	excludePattern := regexp.MustCompile(`failed to parse|[\^%;+']|^$|(/[^/]+){20,}`)
	excludeExts := regexp.MustCompile(`\.(jpg|png|svg|css|gif|jpeg|woff|woff2)$`)
	httpPattern := regexp.MustCompile(`^http`)

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		if excludePattern.MatchString(url) {
			continue
		}
		if excludeExts.MatchString(url) {
			continue
		}
		if !httpPattern.MatchString(url) {
			continue
		}
		if !strings.Contains(url, domain) {
			continue
		}
		filtered = append(filtered, url)
	}
	return filtered
}

// QSReplace replaces query string values (like qsreplace tool)
func QSReplace(url, replacement string) string {
	if idx := strings.Index(url, "="); idx != -1 {
		return url[:idx+1] + replacement
	}
	return url
}

// Anew appends unique lines to file (like anew tool) with URL normalization
func Anew(filepath string, lines []string) error {
	existing := make(map[string]bool)
	originalLines := make(map[string]string) // normalized -> original

	// Read existing file
	if data, err := os.ReadFile(filepath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				// Normalize for comparison
				normalized := line
				if strings.HasPrefix(line, "http") {
					normalized = NormalizeURL(line)
				} else {
					normalized = NormalizeDomain(line)
				}
				existing[normalized] = true
				originalLines[normalized] = line
			}
		}
	}

	// Append new unique lines
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	added := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Normalize for comparison
		normalized := line
		if strings.HasPrefix(line, "http") {
			normalized = NormalizeURL(line)
		} else {
			normalized = NormalizeDomain(line)
		}

		if !existing[normalized] {
			existing[normalized] = true
			originalLines[normalized] = line
			fmt.Fprintln(file, line)
			added++
		}
	}

	return nil
}

// AnewDomains saves domains with deduplication
func AnewDomains(filepath string, domains []string) error {
	existing := make(map[string]bool)

	// Read existing file
	if data, err := os.ReadFile(filepath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				normalized := NormalizeDomain(line)
				existing[normalized] = true
			}
		}
	}

	// Create or append to file
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		normalized := NormalizeDomain(domain)
		if normalized == "" {
			continue
		}

		if !existing[normalized] {
			existing[normalized] = true
			fmt.Fprintln(file, domain)
		}
	}

	return nil
}

// EnumerateSubdomains runs subdomain enumeration tools
func EnumerateSubdomains(domain, outputFile string) error {
	// Check skip
	if ShouldSkip() {
		ResetSkip()
		return nil
	}

	fmt.Printf("%sRunning subfinder...%s\n", utils.Cyan, utils.NC)

	// Run subfinder
	if output, err := RunCommand("subfinder", "-d", domain, "-silent", "-all"); err == nil {
		// Sort and deduplicate
		unique := make(map[string]bool)
		for _, sub := range output {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				unique[sub] = true
			}
		}
		var subs []string
		for sub := range unique {
			subs = append(subs, sub)
		}
		Anew(outputFile, subs)
	}

	fmt.Printf("%sRunning assetfinder...%s\n", utils.Cyan, utils.NC)
	
	// Run assetfinder
	if output, err := RunCommand("assetfinder", "--subs-only", domain); err == nil {
		var subs []string
		for _, sub := range output {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				subs = append(subs, sub)
			}
		}
		Anew(outputFile, subs)
	}

	// Count subdomains
	if data, err := os.ReadFile(outputFile); err == nil {
		lines := strings.Split(string(data), "\n")
		count := 0
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		fmt.Printf("%sNumber of subdomain: %d%s\n", utils.Cyan, count, utils.NC)
	}

	// Filter with httpx
	fmt.Printf("%sFiltering and validating subdomains...%s\n", utils.Cyan, utils.NC)
	subsFile := strings.Replace(outputFile, "all_subdomains.txt", "subs.txt", 1)
	
	if data, err := os.ReadFile(outputFile); err == nil {
		subs := strings.Split(string(data), "\n")
		var alive []string
		for _, sub := range subs {
			sub = strings.TrimSpace(sub)
			if sub == "" {
				continue
			}
			// Run httpx
			if output, err := RunCommand("httpx", "-u", sub, "-t", "80", "-mc", "200,300,301,302,308,307", "-silent"); err == nil {
				for _, line := range output {
					line = strings.TrimSpace(line)
					if line != "" {
						alive = append(alive, line)
					}
				}
			}
		}
		Anew(subsFile, alive)
		
		if data, err := os.ReadFile(subsFile); err == nil {
			lines := strings.Split(string(data), "\n")
			count := 0
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
			fmt.Printf("%sNumber of subdomain a live: %d%s\n", utils.Cyan, count, utils.NC)
		}
	}

	return nil
}

// PerformTask runs all URL collection tools
func PerformTask(domain, targetFile string) error {
	// Check skip at start
	if ShouldSkip() {
		ResetSkip()
		return nil
	}

	// 1. urlfinder
	fmt.Printf("%sFetching URLs by urlfinder for %s...%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommand("urlfinder", "-d", domain, "-all", "-silent"); err == nil {
		filtered := FilterURLs(output, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 2. katana
	fmt.Printf("%sFetching URLs by katana for %s...%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommand("katana", "-u", fmt.Sprintf("https://%s", domain), "-silent", "-sc", "-jc", "-d", "20"); err == nil {
		filtered := FilterURLs(output, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 3. wayback (gau/hakrawler/waybackurls)
	fmt.Printf("%sFetching URLs for by wayback %s#..%s\n", utils.Yellow, domain, utils.NC)
	tools := []string{"gau", "hakrawler", "waybackurls"}
	for _, tool := range tools {
		if output, err := RunCommandWithInput(domain, tool); err == nil {
			filtered := FilterURLs(output, domain)
			for i := range filtered {
				filtered[i] = QSReplace(filtered[i], "")
			}
			Anew(targetFile, filtered)
			break // Use first available tool
		}
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 4. gau
	fmt.Printf("%sFetching URLs for by wayback %s##.%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommandWithInput(domain, "gau"); err == nil {
		filtered := FilterURLs(output, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 5. gauplus
	fmt.Printf("%sFetching URLs for by wayback %s###%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommand("gauplus", "-random-agent", "-t", "10", domain); err == nil {
		filtered := FilterURLs(output, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 6. web.archive.org
	fmt.Printf("%sFetching URLs by web.archive for %s...%s\n", utils.Yellow, domain, utils.NC)
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=text&fl=original&collapse=urlkey", domain)
	if output, err := RunCommand("curl", "-s", url); err == nil {
		filtered := FilterURLs(output, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 7. gospider
	fmt.Printf("%sFetching URLs by gospider for %s...%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommand("gospider", "-s", fmt.Sprintf("https://%s", domain), "-c", "10", "-d", "5", "--blacklist", ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)", "-q"); err == nil {
		// Extract URLs from gospider output
		var urls []string
		urlPattern := regexp.MustCompile(`https?://[^\s]+`)
		for _, line := range output {
			matches := urlPattern.FindAllString(line, -1)
			urls = append(urls, matches...)
		}
		filtered := FilterURLs(urls, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}
	if ShouldSkip() { ResetSkip(); return nil }

	// 8. cariddi
	fmt.Printf("%sFetching URLs by cariddi for %s...%s\n", utils.Yellow, domain, utils.NC)
	cmd := exec.Command("cariddi", "-intensive", "-t", "50", "-rua")
	cmd.Stdin = strings.NewReader(domain)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		var urls []string
		urlPattern := regexp.MustCompile(`https?://[^\s]+`)
		for _, line := range lines {
			matches := urlPattern.FindAllString(line, -1)
			urls = append(urls, matches...)
		}
		filtered := FilterURLs(urls, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}

	// 9. getJS
	fmt.Printf("%sFetching URLs by online for %s...%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommandWithInput(fmt.Sprintf("https://%s", domain), "getJS", "--complete"); err == nil {
		filtered := FilterURLs(output, domain)
		Anew(targetFile, filtered)
	}

	// 10. Extract JS variables
	fmt.Printf("%sFetching URLs and searching for potential XSS by JS variables for %s...%s\n", utils.Yellow, domain, utils.NC)
	extractJSVariables(targetFile, domain)

	return nil
}

// ExtractJSVariables extracts JavaScript variables from URLs
func extractJSVariables(targetFile, domain string) {
	data, err := os.ReadFile(targetFile)
	if err != nil {
		return
	}

	urls := strings.Split(string(data), "\n")
	varPattern := regexp.MustCompile(`var\s+([a-zA-Z0-9_]+)`)
	excludeExts := regexp.MustCompile(`\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt|pdf|json|xml)$`)

	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" || !strings.Contains(url, domain) {
			continue
		}
		if excludeExts.MatchString(strings.ToLower(url)) {
			continue
		}

		// Fetch page
		output, err := RunCommand("curl", "-s", "--max-time", "10", url)
		if err != nil {
			continue
		}

		// Extract variables
		body := strings.Join(output, "\n")
		matches := varPattern.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 1 {
				varName := match[1]
				newURL := fmt.Sprintf("%s?%s=", url, varName)
				if !strings.Contains(newURL, ".js") {
					var urls []string
					urls = append(urls, newURL)
					Anew(targetFile, urls)
				}
			}
		}
	}
}

// PerformTaskSubdomain runs URL collection for subdomains
func PerformTaskSubdomain(domain, targetFile, subsFile string) error {
	// urlfinder with subdomain list
	fmt.Printf("%sFetching URLs by urlfinder for %s...%s\n", utils.Yellow, domain, utils.NC)
	if output, err := RunCommand("urlfinder", "-d", domain, "-all", "-silent"); err == nil {
		filtered := FilterURLs(output, domain)
		for i := range filtered {
			filtered[i] = QSReplace(filtered[i], "")
		}
		Anew(targetFile, filtered)
	}

	if _, err := os.Stat(subsFile); err == nil {
		if output, err := RunCommand("urlfinder", "-list", subsFile, "-all", "-silent"); err == nil {
			filtered := FilterURLs(output, domain)
			for i := range filtered {
				filtered[i] = QSReplace(filtered[i], "")
			}
			Anew(targetFile, filtered)
		}

		// katana with subdomain list
		fmt.Printf("%sFetching URLs by katana for %s...%s\n", utils.Yellow, domain, utils.NC)
		if output, err := RunCommand("katana", "-u", subsFile, "-silent", "-sc", "-jc", "-d", "20"); err == nil {
			filtered := FilterURLs(output, domain)
			for i := range filtered {
				filtered[i] = QSReplace(filtered[i], "")
			}
			Anew(targetFile, filtered)
		}

		// wayback with subdomain list
		fmt.Printf("%sFetching URLs by wayback for %s...%s\n", utils.Yellow, domain, utils.NC)
		if data, err := os.ReadFile(subsFile); err == nil {
			subs := strings.Split(string(data), "\n")
			for _, sub := range subs {
				sub = strings.TrimSpace(sub)
				if sub == "" {
					continue
				}
				tools := []string{"gau", "hakrawler", "waybackurls"}
				for _, tool := range tools {
					if output, err := RunCommandWithInput(sub, tool); err == nil {
						filtered := FilterURLs(output, domain)
						for i := range filtered {
							filtered[i] = QSReplace(filtered[i], "")
						}
						Anew(targetFile, filtered)
						break
					}
				}
			}
		}

		// gospider with subdomain list
		fmt.Printf("%sFetching URLs by gospider for %s...%s\n", utils.Yellow, domain, utils.NC)
		if output, err := RunCommand("gospider", "-S", subsFile, "-c", "10", "-d", "5", "--blacklist", ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)", "-q"); err == nil {
			var urls []string
			urlPattern := regexp.MustCompile(`https?://[^\s]+`)
			for _, line := range output {
				matches := urlPattern.FindAllString(line, -1)
				urls = append(urls, matches...)
			}
			filtered := FilterURLs(urls, domain)
			for i := range filtered {
				filtered[i] = QSReplace(filtered[i], "")
			}
			Anew(targetFile, filtered)
		}

		// cariddi with subdomain list
		fmt.Printf("%sFetching URLs by cariddi for %s...%s\n", utils.Yellow, domain, utils.NC)
		if data, err := os.ReadFile(subsFile); err == nil {
			cmd := exec.Command("cariddi", "-intensive", "-t", "50", "-rua")
			cmd.Stdin = strings.NewReader(string(data))
			output, err := cmd.Output()
			if err == nil {
				lines := strings.Split(string(output), "\n")
				var urls []string
				urlPattern := regexp.MustCompile(`https?://[^\s]+`)
				for _, line := range lines {
					matches := urlPattern.FindAllString(line, -1)
					urls = append(urls, matches...)
				}
				filtered := FilterURLs(urls, domain)
				for i := range filtered {
					filtered[i] = QSReplace(filtered[i], "")
				}
				Anew(targetFile, filtered)
			}
		}

		// getJS with subdomain list
		fmt.Printf("%sFetching URLs by online tools for %s...%s\n", utils.Yellow, domain, utils.NC)
		if data, err := os.ReadFile(subsFile); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				sub := strings.TrimSpace(scanner.Text())
				if sub == "" {
					continue
				}
				if output, err := RunCommandWithInput(fmt.Sprintf("https://%s", sub), "getJS", "--complete"); err == nil {
					filtered := FilterURLs(output, domain)
					Anew(targetFile, filtered)
				}
			}
		}
	}

	return nil
}

