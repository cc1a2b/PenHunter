package encoders

import "encoding/base64"

func Base64Encode(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

