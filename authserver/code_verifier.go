package authserver

import (
	"crypto/sha256"
	"fmt"
)

func CreateCodeChallenge(codeVerifier string) (codeChallenge string) {
	codeChallenge = string(sha256.New().Sum([]byte(codeVerifier)))
	return
}

func VerifyCodeChallenge(codeChallenge, codeVerifier string) error {
	expectedChallenge := CreateCodeChallenge(codeVerifier)
	if codeChallenge != expectedChallenge {
		return fmt.Errorf("expected %s but got %s", expectedChallenge, codeChallenge)
	}
	return nil
}
