package oauthclient

import (
	"encoding/json"
	"net/http"

	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/cap/oidc/callback"
)

type callbackParams struct {
	Claims interface{}
}

func (client *Client) success(state string, t oidc.Token, rw http.ResponseWriter, req *http.Request) {
	var claims map[string]interface{}
	if err := t.IDToken().Claims(&claims); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
	}

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(claims); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
	}
}

func (client *Client) failure(state string, r *callback.AuthenErrorResponse, e error, rw http.ResponseWriter, req *http.Request) {
	http.Error(rw, e.Error(), http.StatusBadRequest)
}

func (client *Client) ServeCallback(rw http.ResponseWriter, req *http.Request) {
	handler, err := callback.AuthCode(req.Context(), client.oidcProvider, client.cache, client.success, client.failure)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	handler(rw, req)
}
