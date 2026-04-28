package scanners

import (
	"bytes"
	"strings"
	"time"

	"penhunter/types"
)

type CSRFScanner struct {
	*BaseScanner
	payloads []string
}

func NewCSRFScanner(encoders []string) *CSRFScanner {
	// CSRF detection payloads - these test if actions can be performed without tokens
	payloads := []string{
		"test",
		"success",
		"completed",
		"csrf_test_value",
		"penhunter_csrf_probe",
	}

	return &CSRFScanner{
		BaseScanner: NewBaseScanner("CSRF", "medium", encoders),
		payloads:    payloads,
	}
}

func (c *CSRFScanner) Payloads() []string {
	return c.payloads
}

func (c *CSRFScanner) Detect(resp *types.HttpResponse) bool {
	body := strings.ToLower(string(resp.Body))

	// Check for success indicators
	successIndicators := []string{
		"success",
		"completed",
		"updated",
		"created",
		"deleted",
		"modified",
		"changed",
	}

	for _, indicator := range successIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}

func (c *CSRFScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
	var findings []*types.Finding

	params := c.extractParameters(targetURL)

	for _, payload := range c.payloads {
		variants := c.mutatePayload(payload)

		for _, variant := range variants {
			// Try POST request
			bodyData := bytes.NewBufferString(variant)
			resp, err := client.Post(targetURL, map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}, bodyData)

			if err == nil && c.Detect(resp) {
				evidence := "CSRF vulnerability detected - action completed without token"
				confidence := 0.7

				finding := c.createFinding(
					targetURL,
					"POST body",
					variant,
					evidence,
					confidence,
					resp.StatusCode,
					string(resp.Body),
				)

				findings = append(findings, finding)
			}

			// Try GET with parameters
			if len(params) > 0 {
				for _, param := range params {
					parts := strings.SplitN(param, "=", 2)
					if len(parts) != 2 {
						continue
					}

					paramName := parts[0]
					injectedURL := c.injectPayload(targetURL, variant)

					resp, err := client.Get(injectedURL, nil)
					if err != nil {
						continue
					}

					if c.Detect(resp) {
						evidence := "CSRF vulnerability detected"
						confidence := 0.7

						finding := c.createFinding(
							injectedURL,
							paramName,
							variant,
							evidence,
							confidence,
							resp.StatusCode,
							string(resp.Body),
						)

						findings = append(findings, finding)
					}
				}
			}

			time.Sleep(50 * time.Millisecond)
		}
	}

	return findings
}

