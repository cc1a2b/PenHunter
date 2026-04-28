package encoders

import "net/url"

func URLEncode(payload string) string {
	return url.QueryEscape(payload)
}

