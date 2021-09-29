package authserver

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/arianvp/webauthn-oidc/util"
)

type RegistrationRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
}

type RegistrationResponse struct {
	ClientID string `json:"client_id"`
}

func (server *AuthorizationServer) handleRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var registrationRequest RegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&registrationRequest); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO limit size?
	var redirectURIs []*url.URL
	for _, rawurl := range registrationRequest.RedirectURIs {
		url, err := url.Parse(rawurl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return

		}
		redirectURIs = append(redirectURIs, url)
	}

	clientID, err := util.RegisterClient(redirectURIs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	registrationResponse := RegistrationResponse{
		ClientID: clientID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(registrationResponse)
}
