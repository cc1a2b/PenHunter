package core

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cc1a2b/PenHunter/types"
)


type HttpClient struct {
	client      *http.Client
	userAgents  []string
	currentUA   int
	rateLimiter *RateLimiter
}

func NewHttpClient(threads int) *HttpClient {
	// Custom TLS config for fingerprint randomization
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects but limit to 10
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	}

	return &HttpClient{
		client:      client,
		userAgents:  userAgents,
		currentUA:   0,
		rateLimiter: NewRateLimiter(threads),
	}
}

func (c *HttpClient) Get(targetURL string, headers map[string]string) (*types.HttpResponse, error) {
	// Rate limiting per host
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	host := parsedURL.Host
	c.rateLimiter.Wait(host)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Rotate User-Agent
	c.currentUA = (c.currentUA + 1) % len(c.userAgents)
	req.Header.Set("User-Agent", c.userAgents[c.currentUA])

	// Add custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Header mutation for WAF evasion
	c.mutateHeaders(req)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &types.HttpResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		URL:        targetURL,
		Duration:   duration,
	}, nil
}

func (c *HttpClient) Post(targetURL string, headers map[string]string, body interface{}) (*types.HttpResponse, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	host := parsedURL.Host
	c.rateLimiter.Wait(host)

	var bodyReader io.Reader
	switch v := body.(type) {
	case io.Reader:
		bodyReader = v
	case []byte:
		bodyReader = bytes.NewReader(v)
	case string:
		bodyReader = strings.NewReader(v)
	default:
		return nil, fmt.Errorf("unsupported body type")
	}
	req, err := http.NewRequest("POST", targetURL, bodyReader)
	if err != nil {
		return nil, err
	}

	c.currentUA = (c.currentUA + 1) % len(c.userAgents)
	req.Header.Set("User-Agent", c.userAgents[c.currentUA])

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	c.mutateHeaders(req)

	start := time.Now()
	resp, err := c.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &types.HttpResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		URL:        targetURL,
		Duration:   duration,
	}, nil
}

func (c *HttpClient) mutateHeaders(req *http.Request) {
	// Random header order and additional headers for WAF evasion
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", "max-age=0")
}

type RateLimiter struct {
	hostLimits map[string]*time.Ticker
	globalTick *time.Ticker
	mu         sync.Mutex
}

func NewRateLimiter(threads int) *RateLimiter {
	interval := time.Second / time.Duration(threads*2) // Adaptive rate
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}

	return &RateLimiter{
		hostLimits: make(map[string]*time.Ticker),
		globalTick: time.NewTicker(interval),
	}
}

func (rl *RateLimiter) Wait(host string) {
	// Per-host rate limiting with mutex protection
	rl.mu.Lock()
	ticker, exists := rl.hostLimits[host]
	if !exists {
		ticker = time.NewTicker(100 * time.Millisecond)
		rl.hostLimits[host] = ticker
	}
	rl.mu.Unlock()

	<-ticker.C

	// Global rate limiting
	<-rl.globalTick.C
}

