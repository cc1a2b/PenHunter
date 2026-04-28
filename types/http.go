package types

import (
	"net/http"
	"time"
)

type HttpResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	URL        string
	Duration   time.Duration
}

type HttpClient interface {
	Get(targetURL string, headers map[string]string) (*HttpResponse, error)
	Post(targetURL string, headers map[string]string, body interface{}) (*HttpResponse, error)
}

