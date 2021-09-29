package authserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"embed"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/gorilla/sessions"
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
	Issuer                        string                          `json:"issuer"`
	AuthEndpoint                  string                          `json:"authorization_endpoint"`
	TokenEndpoint                 string                          `json:"token_endpoint"`
	JWKSURI                       string                          `json:"jwks_uri"`
	UserinfoEndpoint              string                          `json:"userinfo_endpoint,omitempty"`
	SupportedAlgs                 []oidc.Alg                      `json:"id_token_signing_alg_values_supported"`
	SupportedScopes               []string                        `json:"scopes_supported"`
	SubjectTypesSupported         []string                        `json:"subject_types_supported"`
	ResponseTypesSupported        []string                        `json:"response_types_supported"`
	GrantTypesSupported           []string                        `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string                        `json:"code_challenge_methods_supported"`
	ACRValuesSupported            []protocol.ConveyancePreference `json:"acr_values_supported"`
}

type AuthorizationServer struct {
	http.ServeMux

	origin string
	rpID   string

	codeCache *codeCache

	jwks jose.JSONWebKeySet

	privateKey *ecdsa.PrivateKey

	config *OpenidConfiguration

	sessionStore *sessions.CookieStore
}

// TODO because we are dynamic we must support implict and code grant
func New(rpID string, origin string) (*AuthorizationServer, error) {
	server := AuthorizationServer{}
	server.rpID = rpID
	server.origin = origin
	server.codeCache = newCodeCache()

	var err error
	server.privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)

	if _, err := rand.Reader.Read(key); err != nil {
		return nil, err
	}

	sessionStore := sessions.NewCookieStore(key)
	server.sessionStore = sessionStore

	server.jwks.Keys = []jose.JSONWebKey{
		{
			Key:       &server.privateKey.PublicKey,
			KeyID:     "lol",
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}

	server.config = &OpenidConfiguration{
		Issuer:                        origin,
		AuthEndpoint:                  origin + authorize,
		TokenEndpoint:                 origin + token,
		JWKSURI:                       origin + wellKnownJwks,
		UserinfoEndpoint:              origin + userinfo,
		SupportedAlgs:                 []oidc.Alg{oidc.EdDSA, oidc.ES256},
		SupportedScopes:               []string{"openid"},
		SubjectTypesSupported:         []string{"pairwise"}, // the subject is the hash of credential_id+public_key+origin
		ResponseTypesSupported:        []string{"code"},
		CodeChallengeMethodsSupported: []string{"S256"},
	}

	server.Handle(openidConfiguration, http.HandlerFunc(server.handleOpenidConfiguration))
	server.Handle(authorize, http.HandlerFunc(server.handleAuthorize))
	server.Handle(token, http.HandlerFunc(server.handleToken))
	server.Handle(wellKnownJwks, http.HandlerFunc(server.handleWellknownJwks))

	return &server, nil
}

func (server *AuthorizationServer) handleOpenidConfiguration(w http.ResponseWriter, req *http.Request) {
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

func (server *AuthorizationServer) handleWellknownJwks(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(server.jwks); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
