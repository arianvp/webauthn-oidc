package authserver

import (
	"crypto/rand"
	"crypto/rsa"
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
	codeCache.newCode(&state{
		codeChallenge:       "",
		codeChallengeMethod: "",
		redirectURI:         "",
		nonce:               "",
		authTime:            0,
		credential:          &webauthn.Credential{},
	})

	tokenResource = TokenResource{
		origin:          "https://localhost",
		codeCache:       codeCache,
		privateJWKs:     jose.JSONWebKeySet{Keys: []jose.JSONWebKey{privateRSAJWK}},
		clientSecretKey: []byte{},
	}
}

func TestClientIDClientSecretBasicAuthWorks(t *testing.T) {

	tokenRequest := make(url.Values)
	req := httptest.NewRequest(http.MethodPost, tokenResource.origin+"/token", strings.NewReader(tokenRequest.Encode()))
	expectedClient, _ := RegisterClient(tokenResource.clientSecretKey, "")
	req.SetBasicAuth(expectedClient.ClientID, expectedClient.ClientSecret)

	rw := httptest.NewRecorder()
	tokenResource.ServeHTTP(rw, req)

	if rw.Result().StatusCode != 200 {
		t.Errorf("Expected %d but got %d", 200, rw.Result().StatusCode)
	}
}

func TestClientIDClientSecretFormPostWorks(t *testing.T) {

}

func TestClientIDCodeVerifierWorks(t *testing.T) {

}

func TestClientIDClientSecretBasicAuthCodeVerifierWorks(t *testing.T) {

}

func TestClientIDClientSecretFormPostCodeVerifierWorks(t *testing.T) {

}

func TestClientIDWrongClientSecretDoesNotWork(t *testing.T) {

}

func TestClientIDWrongClientSecretVerifierDoesNotWork(t *testing.T) {

}
