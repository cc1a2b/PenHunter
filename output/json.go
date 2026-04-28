package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cc1a2b/PenHunter/types"
)

type JSONHandler struct {
	filename string
}

func NewJSONHandler(filename string) *JSONHandler {
	return &JSONHandler{filename: filename}
}

// JSONReport represents the full report structure
type JSONReport struct {
	Meta     ReportMeta        `json:"meta"`
	Findings []*types.Finding `json:"findings"`
}

// ReportMeta contains report metadata
type ReportMeta struct {
	Generator   string `json:"generator"`
	Version     string `json:"version"`
	GeneratedAt string `json:"generated_at"`
	TotalCount  int    `json:"total_findings"`
}

func (h *JSONHandler) WriteResults(findings []*types.Finding) error {
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

	// Deduplicate findings
	seen := make(map[string]bool)
	uniqueFindings := make([]*types.Finding, 0)

	for _, finding := range findings {
		key := fmt.Sprintf("%s|%s|%s|%s", finding.URL, finding.Parameter, finding.Payload, finding.Scanner)
		if !seen[key] {
			seen[key] = true
			uniqueFindings = append(uniqueFindings, finding)
		}
	}

	// Create report with metadata
	report := JSONReport{
		Meta: ReportMeta{
			Generator:   "PenHunter",
			Version:     "0.1",
			GeneratedAt: time.Now().Format(time.RFC3339),
			TotalCount:  len(uniqueFindings),
		},
		Findings: uniqueFindings,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(report)
}

