package util

import (
	"crypto/sha256"
	"encoding/base64"
)

func RegisterClient(redirectURI string) string {
	hash := sha256.Sum256([]byte(redirectURI))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
