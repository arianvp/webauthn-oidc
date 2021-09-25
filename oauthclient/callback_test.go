package oauthclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestItServesAPage(t *testing.T) {
	req, err := http.NewRequest("GET", "/callback", nil)
	if err != nil {
		t.Fatal(err)
	}

	callback := OauthCallback{}
	rr := httptest.NewRecorder()
	callback.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	if contentType := rr.Header().Get("Content-Type"); contentType != "text/html" {
		t.Errorf("handler returned wrong content type: got %v want %v",
			contentType, "text/html")
	}
}

func TestItFailsToParseQuery(t *testing.T) {

	req, err := http.NewRequest("GET", "/callback?%a", nil)
	if err != nil {
		t.Fatal(err)
	}

	callback := OauthCallback{}
	rr := httptest.NewRecorder()
	callback.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}
}
