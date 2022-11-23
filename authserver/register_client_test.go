package authserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterEmptyClient(t *testing.T) {
	server := RegistrationResource{
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
	server := RegistrationResource{
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

	server := RegistrationResource{
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

	server := RegistrationResource{
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
	server := RegistrationResource{
		clientSecretKey: []byte("helllo"),
	}
	req := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected method not allowed")
	}
}

func TestHandleRegisterWorks(t *testing.T) {
	server := RegistrationResource{
		clientSecretKey: []byte("helllo"),
	}
	body := "{\"redirect_uris\":[\"https://localhost\"]}"
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("Expected status_created")
	}
}

func TestRejectsInvalidJSON(t *testing.T) {
	server := RegistrationResource{
		clientSecretKey: []byte("helllo"),
	}
	body := "{\"redirect_uris:[\"https://localhost\"]}"
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected BadRequest")
	}
}

func TestRejectInvalidURI2(t *testing.T) {
	server := RegistrationResource{
		clientSecretKey: []byte("helllo"),
	}
	body := "{\"redirect_uris\":[\"\\nexamplelocalhost\"]}"
	req := httptest.NewRequest("POST", "/register", strings.NewReader(body))
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)
	var x RFC6749Error
	json.NewDecoder(w.Result().Body).Decode(&x)
	if x.ErrorField != "invalid_redirect_uri" {
		t.Errorf("Expected invalid_redirect_uri but got %v", x.ErrorField)
	}
}
