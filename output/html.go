package output

import (
	"html/template"
	"os"
	"penhunter/types"
)

type HTMLHandler struct {
	filename string
}

func NewHTMLHandler(filename string) *HTMLHandler {
	return &HTMLHandler{filename: filename}
}

func (h *HTMLHandler) WriteResults(findings []*types.Finding) error {
	file, err := os.Create(h.filename)
	if err != nil {
		return err
	}
	defer file.Close()

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>PenHunter Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #dc3545; }
        .high { border-left: 5px solid #fd7e14; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        h1 { color: #333; }
        h2 { color: #666; }
        .label { font-weight: bold; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>PenHunter Scan Results</h1>
    <p>Total Findings: {{len .}}</p>
    {{range $i, $f := .}}
    <div class="finding {{$f.Severity}}">
        <h2>Finding #{{$i}}</h2>
        <p><span class="label">URL:</span> {{$f.URL}}</p>
        <p><span class="label">Parameter:</span> {{$f.Parameter}}</p>
        <p><span class="label">Payload:</span> <code>{{$f.Payload}}</code></p>
        <p><span class="label">Evidence:</span></p>
        <pre>{{$f.Evidence}}</pre>
        <p><span class="label">Confidence:</span> {{printf "%.2f" $f.Confidence}}</p>
        <p><span class="label">Severity:</span> {{$f.Severity}}</p>
        <p><span class="label">Scanner:</span> {{$f.Scanner}}</p>
        <p><span class="label">Status Code:</span> {{$f.StatusCode}}</p>
    </div>
    {{end}}
</body>
</html>`

	t, err := template.New("results").Parse(tmpl)
	if err != nil {
		return err
	}

	return t.Execute(file, findings)
}

