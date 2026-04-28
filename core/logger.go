package core

import (
	"fmt"
	"os"
	"time"

	"github.com/cc1a2b/PenHunter/utils"
)

type Logger struct {
	silent bool
}

func NewLogger(silent bool) *Logger {
	return &Logger{silent: silent}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if !l.silent {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(os.Stdout, "[%s] %s\n", utils.Colorize("INFO", utils.Green), msg)
	}
}

func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[%s] %s\n", utils.Colorize("ERROR", utils.Red), msg)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	if !l.silent {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(os.Stderr, "[%s] %s\n", utils.Colorize("WARN", utils.Yellow), msg)
	}
}

func (l *Logger) Success(format string, args ...interface{}) {
	if !l.silent {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(os.Stdout, "[%s] %s\n", utils.Colorize("SUCCESS", utils.Green), msg)
	}
}

func (l *Logger) Vuln(url, param, payload, scanner string) {
	if !l.silent {
		fmt.Fprintf(os.Stdout, "[%s] %s\n", utils.Colorize("VULN", utils.Red), url)
		fmt.Fprintf(os.Stdout, "  Parameter: %s\n", param)
		fmt.Fprintf(os.Stdout, "  Payload: %s\n", payload)
		fmt.Fprintf(os.Stdout, "  Scanner: %s\n", scanner)
	}
}

func (l *Logger) JSONLog(level, message string, fields map[string]interface{}) {
	if l.silent {
		return
	}

	logEntry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"message":   message,
	}

	for k, v := range fields {
		logEntry[k] = v
	}

	// Simple JSON output (could use encoding/json for proper formatting)
	fmt.Fprintf(os.Stdout, "%+v\n", logEntry)
}

