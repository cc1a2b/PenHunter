package core

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cc1a2b/PenHunter/types"
)

// Global skip flag for Ctrl+C handling
var shouldSkip int32

// SetSkip sets the skip flag
func SetSkip(skip bool) {
	if skip {
		atomic.StoreInt32(&shouldSkip, 1)
	} else {
		atomic.StoreInt32(&shouldSkip, 0)
	}
}

// ShouldSkip checks if current operation should be skipped
func ShouldSkip() bool {
	return atomic.LoadInt32(&shouldSkip) == 1
}

// ResetSkip resets the skip flag
func ResetSkip() {
	atomic.StoreInt32(&shouldSkip, 0)
}

type Scanner interface {
	Name() string
	Payloads() []string
	Detect(resp *types.HttpResponse) bool
	Severity() string
	Scan(url string, client types.HttpClient) []*types.Finding
}

type Engine struct {
	threads      int
	logger       *Logger
	scanners     []Scanner
	httpClient   *HttpClient
	runner       *Runner
	findings     []*types.Finding
	findingsLock sync.Mutex
	seenFindings map[string]bool // For deduplication
}

func NewEngine(threads int, logger *Logger) *Engine {
	return &Engine{
		threads:      threads,
		logger:       logger,
		scanners:     make([]Scanner, 0),
		httpClient:   NewHttpClient(threads),
		runner:       NewRunner(threads),
		findings:     make([]*types.Finding, 0),
		seenFindings: make(map[string]bool),
	}
}

// findingKey creates a unique key for a finding to detect duplicates
func (e *Engine) findingKey(finding *types.Finding) string {
	// Normalize URL for comparison
	normalizedURL := NormalizeURL(finding.URL)
	return fmt.Sprintf("%s|%s|%s|%s", normalizedURL, finding.Parameter, finding.Scanner, finding.Severity)
}

// isDuplicate checks if a finding has already been recorded
func (e *Engine) isDuplicate(finding *types.Finding) bool {
	key := e.findingKey(finding)
	return e.seenFindings[key]
}

// markAsSeen marks a finding as seen
func (e *Engine) markAsSeen(finding *types.Finding) {
	key := e.findingKey(finding)
	e.seenFindings[key] = true
}

func (e *Engine) RegisterScanner(scanner Scanner) {
	e.scanners = append(e.scanners, scanner)
}

func (e *Engine) Scan(urls []string) []*types.Finding {
	// Deduplicate input URLs first
	seenURLs := make(map[string]bool)
	uniqueURLs := make([]string, 0)
	for _, u := range urls {
		normalized := NormalizeURL(u)
		if !seenURLs[normalized] {
			seenURLs[normalized] = true
			uniqueURLs = append(uniqueURLs, u)
		}
	}

	duplicatesRemoved := len(urls) - len(uniqueURLs)
	if duplicatesRemoved > 0 {
		e.logger.Info("Removed %d duplicate URLs", duplicatesRemoved)
	}
	e.logger.Info("Scanning %d URLs with %d scanner(s)", len(uniqueURLs), len(e.scanners))

	for _, targetURL := range uniqueURLs {
		// Check if skip was requested
		if ShouldSkip() {
			e.logger.Info("Skipping remaining URLs...")
			ResetSkip()
			break
		}

		for _, scanner := range e.scanners {
			scanner := scanner
			targetURL := targetURL

			e.runner.Submit(func() {
				// Check skip inside goroutine too
				if ShouldSkip() {
					return
				}

				findings := scanner.Scan(targetURL, e.httpClient)
				if len(findings) > 0 {
					e.findingsLock.Lock()
					for _, finding := range findings {
						// Check for duplicates before adding
						if !e.isDuplicate(finding) {
							e.markAsSeen(finding)
							e.findings = append(e.findings, finding)
							e.logger.Vuln(finding.URL, finding.Parameter, finding.Payload, finding.Scanner)
						}
					}
					e.findingsLock.Unlock()
				}
			})
		}
	}

	e.runner.Wait()
	return e.findings
}

func (e *Engine) AddFinding(finding *types.Finding) {
	e.findingsLock.Lock()
	defer e.findingsLock.Unlock()

	// Check for duplicates before adding
	if !e.isDuplicate(finding) {
		e.markAsSeen(finding)
		e.findings = append(e.findings, finding)
	}
}

