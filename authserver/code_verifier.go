package authserver

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func CreateCodeChallenge(codeVerifier string) (codeChallenge string) {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return
}

func VerifyCodeChallenge(codeChallenge, codeVerifier string) error {
	expectedChallenge := CreateCodeChallenge(codeVerifier)
	if codeChallenge != expectedChallenge {
		return fmt.Errorf("expected %s but got %s", expectedChallenge, codeChallenge)
	}
	return nil
}
