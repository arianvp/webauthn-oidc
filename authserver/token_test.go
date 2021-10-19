package authserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/duo-labs/webauthn/webauthn"
	"gopkg.in/square/go-jose.v2"
)

var (
	tokenResource TokenResource
)

func init() {

	clientSecretKey := make([]byte, 32)
	rand.Read(clientSecretKey)

	privateRSAKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateRSAJWK := jose.JSONWebKey{
		Key:       privateRSAKey,
		KeyID:     string(jose.RS256),
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	codeCache := newCodeCache()
	tokenResource = TokenResource{
		origin:          "https://localhost",
		codeCache:       codeCache,
		privateJWKs:     jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateRSAJWK}},
		clientSecretKey: []byte{},
	}
}

func TestClientIDClientSecretWorks(t *testing.T) {
	redirectURI := "https://localhost/redirect"
	code, _ := tokenResource.codeCache.newCode(&state{
		redirectURI: redirectURI,
		nonce:       "blah",
		authTime:    0,
		credential: &webauthn.Credential{
			ID:              []byte{},
			PublicKey:       []byte{},
			AttestationType: "none",
			Authenticator:   webauthn.Authenticator{},
		},
	})
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	tokenRequest := TokenRequest{
		Code:         code,
		GrantType:    "",
		RedirectURI:  redirectURI,
		ClientID:     expectedClient.ClientID,
		ClientSecret: expectedClient.ClientSecret,
	}
	_, err := tokenResource.Handle(tokenRequest)
	if err != nil {
		t.Errorf("Expected a response but got %v", err)
	}
}

func TestClientIDClientSecretBasicAuthWorks(t *testing.T) {
	redirectURI := "https://localhost/redirect"
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	tokenRequest := make(url.Values)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(expectedClient.ClientID, expectedClient.ClientSecret)

	parsedTokenRequest := ParseTokenRequest(req)
	if parsedTokenRequest.ClientID != expectedClient.ClientID {
		t.Errorf("ClientID did not match")
	}
	if parsedTokenRequest.ClientSecret != expectedClient.ClientSecret {
		t.Errorf("ClientSecret did not match")
	}
}

func TestClientSecretFormPostWorks(t *testing.T) {
	redirectURI := "https://localhost/redirect"
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	tokenRequest := make(url.Values)
	tokenRequest.Add("client_id", expectedClient.ClientID)
	tokenRequest.Add("client_secret", expectedClient.ClientSecret)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	parsedTokenRequest := ParseTokenRequest(req)
	if parsedTokenRequest.ClientID != expectedClient.ClientID {
		t.Errorf("ClientID did not match")
	}
	if parsedTokenRequest.ClientSecret != expectedClient.ClientSecret {
		t.Errorf("ClientSecret did not match")
	}

}
func TestClientIDCodeVerifierWorks(t *testing.T) {
	redirectURI := "https://localhost/redirect"
	codeVerifierRaw := make([]byte, 32)
	rand.Read(codeVerifierRaw)
	codeVerifier := base64.RawStdEncoding.EncodeToString(codeVerifierRaw)
	codeChallenge := CreateCodeChallenge(codeVerifier)
	code, _ := tokenResource.codeCache.newCode(&state{
		codeChallenge: codeChallenge,
		redirectURI:   redirectURI,
		nonce:         "blah",
		authTime:      0,
		credential: &webauthn.Credential{
			ID:              []byte{},
			PublicKey:       []byte{},
			AttestationType: "none",
			Authenticator:   webauthn.Authenticator{},
		},
	})
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	tokenRequest := TokenRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		GrantType:    "",
		RedirectURI:  redirectURI,
		ClientID:     expectedClient.ClientID,
		ClientSecret: "",
	}

	_, err := tokenResource.Handle(tokenRequest)

	if err != nil {
		t.Errorf("Expected success but got %v", err)
	}
}

func TestClientIDClientSecretCodeVerifierWorks(t *testing.T) {
	redirectURI := "https://localhost/redirect"
	codeVerifierRaw := make([]byte, 32)
	rand.Read(codeVerifierRaw)
	codeVerifier := base64.RawStdEncoding.EncodeToString(codeVerifierRaw)
	codeChallenge := CreateCodeChallenge(codeVerifier)
	code, _ := tokenResource.codeCache.newCode(&state{
		codeChallenge: codeChallenge,
		redirectURI:   redirectURI,
		nonce:         "blah",
		authTime:      0,
		credential: &webauthn.Credential{
			ID:              []byte{},
			PublicKey:       []byte{},
			AttestationType: "none",
			Authenticator:   webauthn.Authenticator{},
		},
	})
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	tokenRequest := TokenRequest{
		Code:         code,
		CodeVerifier: codeVerifier,
		GrantType:    "",
		RedirectURI:  redirectURI,
		ClientID:     expectedClient.ClientID,
		ClientSecret: expectedClient.ClientSecret,
	}

	_, err := tokenResource.Handle(tokenRequest)

	if err != nil {
		t.Errorf("Expected success but got %v", err)
	}
}

func TestClientIDWrongClientSecretDoesNotWork(t *testing.T) {

}

func TestClientIDWrongClientSecretCodeVerifierDoesNotWork(t *testing.T) {

}

func TestClientIDWrongCodeVerifierDoesNotWork(t *testing.T) {

}

func TestClientIDWrongClientSecretWrongCodeVerifierDoesNotWork(t *testing.T) {

}

func TestRejectsNonPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, tokenResource.origin+"/token", nil)
	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)
	if rw.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected %d but got %d", http.StatusMethodNotAllowed, rw.Result().StatusCode)
	}
}