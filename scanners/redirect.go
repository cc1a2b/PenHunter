package scanners

import (
	"strings"
	"time"

	"penhunter/core"
	"penhunter/types"
)

type RedirectScanner struct {
	*BaseScanner
	payloads       []string
	redirectDomain string
}

func NewRedirectScanner(encoders []string) *RedirectScanner {
	// Get redirect domain from config
	redirectDomain := core.GetRedirectDomain()
	if redirectDomain == "" {
		redirectDomain = "evil.com" // fallback
	}

	// Build payloads using configured domain
	payloads := []string{
		"http://" + redirectDomain,
		"//" + redirectDomain,
		"/\\" + redirectDomain,
		"/%5C" + redirectDomain,
		"%2F" + redirectDomain,
		"http://" + redirectDomain + "/",
		"https://" + redirectDomain,
		"//" + redirectDomain + "/",
		redirectDomain,
		"@" + redirectDomain,
		redirectDomain + "/",
		// Additional bypass techniques
		"http://" + redirectDomain + "%00",
		"http://" + redirectDomain + "%0d%0a",
		"////" + redirectDomain,
		"////\\" + redirectDomain,
		"https://" + redirectDomain + "@legitimate.com",
		"https://legitimate.com@" + redirectDomain,
		"http://" + redirectDomain + "?.legitimate.com",
		"http://" + redirectDomain + "#.legitimate.com",
		"//" + redirectDomain + "/%2f%2e%2e",
	}

	return &RedirectScanner{
		BaseScanner:    NewBaseScanner("OpenRedirect", "medium", encoders),
		payloads:       payloads,
		redirectDomain: redirectDomain,
	}
}

func (r *RedirectScanner) Payloads() []string {
	return r.payloads
}

func (r *RedirectScanner) Detect(resp *types.HttpResponse) bool {
	location := resp.Headers.Get("Location")
	if location == "" {
		return false
	}

	// Check if redirects to configured domain
	testDomains := []string{
		r.redirectDomain,
		"//" + r.redirectDomain,
		"http://" + r.redirectDomain,
		"https://" + r.redirectDomain,
	}

	locationLower := strings.ToLower(location)
	for _, domain := range testDomains {
		if strings.Contains(locationLower, strings.ToLower(domain)) {
			return true
		}
	}

	return false
}

func (r *RedirectScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
	var findings []*types.Finding

	if !r.hasParameter(targetURL) {
		return findings
	}

	params := r.extractParameters(targetURL)
	if len(params) == 0 {
		return findings
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
				injectedURL := r.injectPayload(targetURL, variant)

				resp, err := client.Get(injectedURL, nil)
				if err != nil {
					continue
				}

				if r.Detect(resp) {
					location := resp.Headers.Get("Location")
					evidence := "Redirects to: " + location
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
				}

				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	return findings
}

