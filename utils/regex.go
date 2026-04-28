package utils

import "regexp"

func MatchPattern(pattern, text string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(text)
}

func FindAllMatches(pattern, text string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return []string{}
	}
	return re.FindAllString(text, -1)
}

