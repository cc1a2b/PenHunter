package encoders

import "fmt"

func UnicodeEncode(payload string) string {
	var result string
	for _, char := range payload {
		result += fmt.Sprintf("\\u%04x", char)
	}
	return result
}

