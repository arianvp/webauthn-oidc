package authserver

import "testing"

func TestCodeVerifierExample(t *testing.T) {
	// https://datatracker.ietf.org/doc/html/rfc7636#appendix-B

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	expectedCodeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	myCodeChallenge := CreateCodeChallenge(codeVerifier)

	if myCodeChallenge != expectedCodeChallenge {

		t.Errorf("Code challenge did not match")
	}

}
