package types

type Finding struct {
	URL          string
	Parameter    string
	Payload      string
	Evidence     string
	Confidence   float64
	Severity     string
	Scanner      string
	StatusCode   int
	ResponseBody string
}

