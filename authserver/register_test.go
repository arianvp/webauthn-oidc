package authserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterEmptyClient(t *testing.T) {
	server := AuthorizationServer{
		clientSecretKey: []byte("helllo"),
	}
	response, err := server.RegisterClient(RegistrationRequest{
		RedirectURIs: []string{},
	})
	if err == nil && response != nil {
		t.Errorf("Expected an error but got response")
	}
}

func TestRegisterOneClient(t *testing.T) {
	server := AuthorizationServer{
		clientSecretKey: []byte("helllo"),
	}
	response, err := server.RegisterClient(RegistrationRequest{
		RedirectURIs: []string{"https://example.com"},
	})
	if err != nil && response == nil {
		t.Errorf("Expected an a response but got an error")
	}
	if response.ClientID == "" {
		t.Errorf("Expected an a ClientID but got nothing")
	}
	if response.ClientSecret == "" {
		t.Errorf("Expected an a ClientID but got nothing")
	}
}

func TestRegisterMultipleURIs(t *testing.T) {

	server := AuthorizationServer{
		clientSecretKey: []byte("helllo"),
	}
	_, err := server.RegisterClient(RegistrationRequest{
		RedirectURIs: []string{"https://example.com", "https://a.example.com"},
	})
	if err == nil {
		t.Errorf("Expected multiple redirect_uris to be rejected")
	}
}
func TestRegisterInvalidURI(t *testing.T) {

	server := AuthorizationServer{
		clientSecretKey: []byte("helllo"),
	}
	_, err := server.RegisterClient(RegistrationRequest{
		RedirectURIs: []string{"\nexample.com"},
	})
	if err == nil {
		t.Errorf("Expected invalid URI to be rejected")
	}
}

func TestHandleRegisterRejcetsGet(t *testing.T) {
	server := AuthorizationServer{
		clientSecretKey: []byte("helllo"),
	}
	req := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()
	server.handleRegister(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected method not allowed")
	}
}
