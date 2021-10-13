package authserver

import (
	"crypto/sha256"
	"fmt"
)

type codeVerifier struct {
	challenge string
	verifier  string
	method    string
}

func (v *codeVerifier) Verify() error {
	if v.method != "S256" {
		return fmt.Errorf("expected %s but got %s", "S256", v.method)
	}
	challenge := sha256.Sum256([]byte(v.verifier))
	expectedChallenge := string(challenge[:])

	if v.challenge != expectedChallenge {
		return fmt.Errorf("expected %s but got %s", expectedChallenge, v.challenge)
	}
	return nil
}
