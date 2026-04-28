package output

import (
	"fmt"
	"os"
	"time"

	"penhunter/types"
)

type TXTHandler struct {
	filename string
}

func NewTXTHandler(filename string) *TXTHandler {
	return &TXTHandler{filename: filename}
}

func (h *TXTHandler) WriteResults(findings []*types.Finding) error {
	var file *os.File
	var err error

	if h.filename == "" {
		file = os.Stdout
	} else {
		file, err = os.Create(h.filename)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	// Write header
	fmt.Fprintf(file, "================================================================================\n")
	fmt.Fprintf(file, "                         PenHunter - Vulnerability Report\n")
	fmt.Fprintf(file, "================================================================================\n")
	fmt.Fprintf(file, "Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Total Findings: %d\n", len(findings))
	fmt.Fprintf(file, "================================================================================\n\n")

	// Deduplicate findings before writing
	seen := make(map[string]bool)
	uniqueFindings := make([]*types.Finding, 0)

	for _, finding := range findings {
		// Create unique key for deduplication
		key := fmt.Sprintf("%s|%s|%s|%s", finding.URL, finding.Parameter, finding.Payload, finding.Scanner)
		if !seen[key] {
			seen[key] = true
			uniqueFindings = append(uniqueFindings, finding)
		}
	}

	for i, finding := range uniqueFindings {
		fmt.Fprintf(file, "=== Finding %d ===\n", i+1)
		fmt.Fprintf(file, "URL: %s\n", finding.URL)
		fmt.Fprintf(file, "Parameter: %s\n", finding.Parameter)
		fmt.Fprintf(file, "Payload: %s\n", finding.Payload)
		fmt.Fprintf(file, "Evidence: %s\n", finding.Evidence)
		fmt.Fprintf(file, "Confidence: %.2f\n", finding.Confidence)
		fmt.Fprintf(file, "Severity: %s\n", finding.Severity)
		fmt.Fprintf(file, "Scanner: %s\n", finding.Scanner)
		fmt.Fprintf(file, "Status Code: %d\n", finding.StatusCode)
		fmt.Fprintf(file, "\n")
	}

	// Write footer
	fmt.Fprintf(file, "================================================================================\n")
	fmt.Fprintf(file, "                              End of Report\n")
	fmt.Fprintf(file, "================================================================================\n")

	return nil
}

