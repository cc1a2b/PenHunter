package utils

import (
	"math/rand"
	"time"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rng.Intn(len(charset))]
	}
	return string(b)
}

func RandomInt(min, max int) int {
	return rng.Intn(max-min) + min
}

func Jitter(base time.Duration, percent int) time.Duration {
	jitter := time.Duration(rng.Intn(percent)) * base / 100
	return base + jitter
}

