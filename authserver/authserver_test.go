package authserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllEndpointsReachable(t *testing.T) {
	rpID := "localhost"
	origin := "https://localhost:6443"
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cookieKey := make([]byte, 64)
	rand.Reader.Read(cookieKey)
	clientSecretKey := make([]byte, 64)
	rand.Reader.Read(clientSecretKey)
	authserver := New(rpID, origin, ecdsaKey, [][]byte{cookieKey}, clientSecretKey)

	for _, path := range []string{openidConfigurationPath, oauthAuthorizationServerPath, register, authorize, token, userinfo, wellKnownJwks} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("GET", origin+path, nil)

			authserver.ServeHTTP(recorder, req)
			resp := recorder.Result()
			if resp.StatusCode == http.StatusNotFound {
				t.Errorf("Expected endpoint %s to be found", origin+path)
			}

		})
	}

}
