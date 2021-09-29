package authserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/pkg/errors"
)

type RegistrationRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
}

type RegistrationResponse struct {
	ClientID string `json:"client_id,omitempty"`
}

func RegisterClient(req RegistrationRequest) (*RegistrationResponse, error) {
	var origin string
	if len(req.RedirectURIs) == 0 {
		return nil, errors.New("No redirect_uris found")
	}
	for _, redirectURI := range req.RedirectURIs {
		url, err := url.Parse(redirectURI)
		if err != nil {
			return nil, ErrInvalidRedirectURI.WithDescription(err.Error())

		}
		newOrigin := protocol.FullyQualifiedOrigin(url)
		if origin == "" {
			origin = newOrigin
		} else if origin != newOrigin {
			return nil, errors.New("All redirect_uris must have the same origin")
		}
	}
	hash := sha256.Sum256([]byte(origin))
	return &RegistrationResponse{
		ClientID: base64.RawURLEncoding.EncodeToString(hash[:]),
	}, nil
}

func (server *AuthorizationServer) handleRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var registrationRequest RegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&registrationRequest); err != nil {
		ErrInvalidRequest.WithDescription(err.Error()).RespondJSON(w)
		return
	}

	// TODO limit size?
	var redirectURIs []*url.URL
	for _, rawurl := range registrationRequest.RedirectURIs {
		url, err := url.Parse(rawurl)
		if err != nil {
			ErrInvalidRedirectURI.WithDescription(err.Error()).RespondJSON(w)
			return

		}
		redirectURIs = append(redirectURIs, url)
	}

	registrationResponse, err := RegisterClient(registrationRequest)
	if err != nil {
		ErrorToRFC6749Error(err).RespondJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(registrationResponse)
}
