package authserver

import (
	"crypto/ecdsa"
	"embed"
	"net/http"

	"github.com/hashicorp/cap/oidc"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
)

//go:embed *.html
var content embed.FS

const (
	openidConfiguration = "/.well-known/openid-configuration"
	authorize           = "/authorize"
	token               = "/token"
	userinfo            = "/userinfo"
	wellKnownJwks       = "/.well-known/jwks.json"
)

type OpenidConfiguration struct {
	Issuer                 string     `json:"issuer"`
	AuthEndpoint           string     `json:"authorization_endpoint"`
	TokenEndpoint          string     `json:"token_endpoint"`
	JWKSURI                string     `json:"jwks_uri"`
	UserinfoEndpoint       string     `json:"userinfo_endpoint,omitempty"`
	SupportedAlgs          []oidc.Alg `json:"id_token_signing_alg_values_supported"`
	SupportedScopes        []string   `json:"scopes_supported"`
	SubjectTypesSupported  []string   `json:"subject_types_supported"`
	ResponseTypesSupported []string   `json:"response_types_supported"`
	GrantTypesSupported    []string   `json:"grant_types_supported"`
}

type AuthorisationServer struct {
	http.ServeMux

	origin string

	codeCache *codeCache

	jwks *jose.JSONWebKeySet

	privateKey *ecdsa.PrivateKey

	config *OpenidConfiguration
}

// TODO because we are dynamic we must support implict and code grant
func New(origin string) AuthorisationServer {
	server := AuthorisationServer{}
	server.codeCache = newCodeCache()
	server.config = &OpenidConfiguration{
		Issuer:                 origin,
		AuthEndpoint:           origin + authorize,
		TokenEndpoint:          origin + token,
		JWKSURI:                origin + wellKnownJwks,
		UserinfoEndpoint:       origin + userinfo,
		SupportedAlgs:          []oidc.Alg{oidc.ES256},
		SupportedScopes:        []string{"openid"},
		SubjectTypesSupported:  []string{"public"},
		ResponseTypesSupported: []string{"code"},
	}
	server.Handle(openidConfiguration, http.HandlerFunc(server.handleOpenidConfiguration))
	server.Handle(authorize, http.HandlerFunc(server.handleAuthorize))
	server.Handle(token, http.HandlerFunc(server.handleToken))
	server.Handle(wellKnownJwks, http.HandlerFunc(server.handleWellknownJwks))

	return server
}

func (server *AuthorisationServer) handleOpenidConfiguration(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(server.config); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}
}

func (server *AuthorisationServer) handleWellknownJwks(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(server.jwks); err != nil {
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}

}
