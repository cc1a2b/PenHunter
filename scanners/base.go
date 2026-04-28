package scanners

import (
	"net/url"
	"strings"

	"penhunter/encoders"
	"penhunter/types"
)

type BaseScanner struct {
	name      string
	severity  string
	encoders  []string
	encoder   *encoders.Encoder
}

func NewBaseScanner(name, severity string, encoderList []string) *BaseScanner {
	return &BaseScanner{
		name:     name,
		severity: severity,
		encoders: encoderList,
		encoder:  encoders.NewEncoder(encoderList),
	}
}

func (s *BaseScanner) Name() string {
	return s.name
}

func (s *BaseScanner) Severity() string {
	return s.severity
}

func (s *BaseScanner) mutatePayload(payload string) []string {
	variants := []string{payload}

	// Apply encoders
	if s.encoder != nil {
		encoded := s.encoder.Encode(payload)
		variants = append(variants, encoded...)
	}

	return variants
}

func (s *BaseScanner) extractParameters(targetURL string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return []string{}
	}

	var params []string
	for key, values := range parsed.Query() {
		for _, value := range values {
			// Reconstruct parameter
			param := key + "=" + value
			params = append(params, param)
		}
	}

	return params
}

func (s *BaseScanner) injectPayload(targetURL, payload string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	query := parsed.Query()
	if len(query) == 0 {
		// No parameters, add one
		return targetURL + "?test=" + url.QueryEscape(payload)
	}

	// Replace first parameter value
	for key := range query {
		query.Set(key, payload)
		break
	}

	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *BaseScanner) hasParameter(targetURL string) bool {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	return len(parsed.Query()) > 0 || strings.Contains(targetURL, "=")
}

func (s *BaseScanner) createFinding(targetURL, param, payload, evidence string, confidence float64, statusCode int, responseBody string) *types.Finding {
	return &types.Finding{
		URL:          targetURL,
		Parameter:    param,
		Payload:      payload,
		Evidence:     evidence,
		Confidence:   confidence,
		Severity:     s.severity,
		Scanner:      s.name,
		StatusCode:   statusCode,
		ResponseBody: responseBody,
	}
}

