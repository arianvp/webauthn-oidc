package authserver

import (
	"crypto/sha256"
	"fmt"
)

type S256CodeVerifier struct {
	challenge string
	verifier  string
}

func CreateCodeChallenge(codeVerifier string) (codeChallenge string) {
	codeChallenge = string(sha256.New().Sum([]byte(codeVerifier)))
	return
}

func (v *S256CodeVerifier) Verify() error {
	expectedChallenge := CreateCodeChallenge(v.verifier)

	if v.challenge != expectedChallenge {
		return fmt.Errorf("expected %s but got %s", expectedChallenge, v.challenge)
	}
	return nil
}
