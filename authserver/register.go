package authserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
)

type RegistrationResource struct {
	clientSecretKey []byte
}

type RegistrationRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
}

type RegistrationResponse struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func GenerateClientIDRaw(redirectURI string) []byte {
	h := sha256.New()
	h.Write([]byte(redirectURI))
	return h.Sum(nil)
}
func GenerateClientID(redirectURI string) string {
	return base64.RawURLEncoding.EncodeToString(GenerateClientIDRaw(redirectURI))
}

func RegisterClient(clientSecretKey []byte, redirectURI string) (*RegistrationResponse, error) {
	_, err := url.Parse(redirectURI)
	if err != nil {
		return nil, ErrInvalidRedirectURI.WithDescription(err.Error())

	}
	clientIDRaw := GenerateClientIDRaw(redirectURI)
	hmacer := hmac.New(sha256.New, clientSecretKey)
	hmacer.Write(clientIDRaw)
	clientSecretRaw := hmacer.Sum(nil)
	return &RegistrationResponse{
		ClientID:     base64.RawURLEncoding.EncodeToString(clientIDRaw),
		ClientSecret: base64.RawURLEncoding.EncodeToString(clientSecretRaw),
	}, nil
}

func (r *RegistrationResource) RegisterClient(req RegistrationRequest) (*RegistrationResponse, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, errors.New("No redirect_uris found")
	}
	if len(req.RedirectURIs) > 1 {
		return nil, errors.New("Only one redirect_uri can currently be registered per client")
	}
	return RegisterClient(r.clientSecretKey, req.RedirectURIs[0])
}

func (r *RegistrationResource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var registrationRequest RegistrationRequest
	if err := json.NewDecoder(req.Body).Decode(&registrationRequest); err != nil {
		ErrInvalidRequest.WithDescription(err.Error()).RespondJSON(w)
		return
	}

	registrationResponse, err := r.RegisterClient(registrationRequest)
	if err != nil {
		ErrorToRFC6749Error(err).RespondJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(registrationResponse)
}
