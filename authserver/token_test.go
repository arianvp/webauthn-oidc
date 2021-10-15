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

func TestRejectsNonPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, tokenResource.origin+"/token", nil)
	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)
	if rw.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected %d but got %d", http.StatusMethodNotAllowed, rw.Result().StatusCode)
	}
}
func TestClientIDClientSecretBasicAuthWorks(t *testing.T) {
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
	tokenRequest := make(url.Values)
	tokenRequest.Add("code", code)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	req.SetBasicAuth(expectedClient.ClientID, expectedClient.ClientSecret)

	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)

	if rw.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected %d but got %d", http.StatusOK, rw.Result().StatusCode)
	}
}

func TestClientIDClientSecretFormPostWorks(t *testing.T) {
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
	tokenRequest := make(url.Values)
	tokenRequest.Add("code", code)
	tokenRequest.Add("client_id", expectedClient.ClientID)
	tokenRequest.Add("client_secret", expectedClient.ClientSecret)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)

	if rw.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected %d but got %d", http.StatusOK, rw.Result().StatusCode)
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
	tokenRequest := make(url.Values)
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	tokenRequest.Add("client_id", expectedClient.ClientID)
	tokenRequest.Add("code", code)
	tokenRequest.Add("code_verifier", codeVerifier)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)

	if rw.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected %d but got %v", http.StatusOK, rw.Result().StatusCode)
	}

}

func TestClientIDClientSecretBasicAuthCodeVerifierWorks(t *testing.T) {
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
	tokenRequest := make(url.Values)
	tokenRequest.Add("code", code)
	tokenRequest.Add("code_verifier", codeVerifier)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, redirectURI)
	req.SetBasicAuth(expectedClient.ClientID, expectedClient.ClientSecret)

	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)

	if rw.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected %d but got %v", http.StatusOK, rw.Result().StatusCode)
	}
}

func TestClientIDClientSecretFormPostCodeVerifierWorks(t *testing.T) {

}

func TestClientIDWrongClientSecretDoesNotWork(t *testing.T) {

}

func TestClientIDWrongClientSecretVerifierDoesNotWork(t *testing.T) {

}
