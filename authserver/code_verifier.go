package authserver

import (
	"crypto/sha256"
	"fmt"
)

type CodeVerifier struct {
	challenge string
	verifier  string
	method    string
}

func CreateCodeChallenge(codeVerifier string) (codeChallenge string) {
	codeChallenge = string(sha256.New().Sum([]byte(codeVerifier)))
	return
}

func (v *CodeVerifier) Verify() error {
	if v.method != "S256" {
		return fmt.Errorf("expected %s but got %s", "S256", v.method)
	}

	expectedChallenge := CreateCodeChallenge(v.verifier)

	if v.challenge != expectedChallenge {
		return fmt.Errorf("expected %s but got %s", expectedChallenge, v.challenge)
	}
	return nil
}
