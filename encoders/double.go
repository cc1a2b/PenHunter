package encoders

import "net/url"

func DoubleEncode(payload string) string {
	encoded := url.QueryEscape(payload)
	return url.QueryEscape(encoded)
}

