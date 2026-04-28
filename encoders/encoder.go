package encoders

type Encoder struct {
	encoders []string
}

func NewEncoder(encoderList []string) *Encoder {
	return &Encoder{
		encoders: encoderList,
	}
}

func (e *Encoder) Encode(payload string) []string {
	var results []string

	for _, encoderName := range e.encoders {
		switch encoderName {
		case "url":
			results = append(results, URLEncode(payload))
		case "base64":
			results = append(results, Base64Encode(payload))
		case "double":
			results = append(results, DoubleEncode(payload))
		case "unicode":
			results = append(results, UnicodeEncode(payload))
		}
	}

	return results
}

