package authserver

import (
	"fmt"

	"github.com/hashicorp/cap/oidc"
)

type codeVerifier struct {
	challenge string
	verifier  string
	method    string
}

func (v *codeVerifier) Verifier() string  { return v.verifier }
func (v *codeVerifier) Challenge() string { return v.challenge }
func (v *codeVerifier) Copy() oidc.CodeVerifier {
	return &codeVerifier{
		challenge: v.challenge,
		verifier:  v.verifier,
		method:    v.method,
	}
}
func (v *codeVerifier) Method() oidc.ChallengeMethod { return oidc.ChallengeMethod(v.method) }

func (v *codeVerifier) Verify() error {
	expectedChallenge, err := oidc.CreateCodeChallenge(v)
	if err != nil {
		return err
	}
	if expectedChallenge != v.challenge {
		return fmt.Errorf("Expected %s but got %s", expectedChallenge, v.challenge)
	}
	return nil
}
