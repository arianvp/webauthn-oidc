package authserver

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"embed"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/gorilla/sessions"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
)

//go:embed *.html
var content embed.FS

const (
	openidConfiguration      = "/.well-known/openid-configuration"
	oauthAuthorizationServer = "/.well-known/oauth-authorization-server"
	register                 = "/register"
	authorize                = "/authorize"
	token                    = "/token"
	userinfo                 = "/userinfo"
	wellKnownJwks            = "/.well-known/jwks.json"
	webFinger                = "/.well-known/webfinger"
)

type OpenidConfiguration struct {
	Issuer                            string                          `json:"issuer"`
	RegistrationEndpoint              string                          `json:"registration_endpoint"`
	AuthEndpoint                      string                          `json:"authorization_endpoint"`
	TokenEndpoint                     string                          `json:"token_endpoint"`
	JWKSURI                           string                          `json:"jwks_uri"`
	UserinfoEndpoint                  string                          `json:"userinfo_endpoint,omitempty"`
	SupportedAlgs                     []jose.SignatureAlgorithm       `json:"id_token_signing_alg_values_supported"`
	SupportedScopes                   []string                        `json:"scopes_supported"`
	SubjectTypesSupported             []string                        `json:"subject_types_supported"`
	ResponseTypesSupported            []string                        `json:"response_types_supported"`
	GrantTypesSupported               []string                        `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string                        `json:"code_challenge_methods_supported"`
	ACRValuesSupported                []protocol.ConveyancePreference `json:"acr_values_supported"`
	TokenEndpointAuthMethodsSupported []string                        `json:"token_endpoint_auth_methods_supported"`
}

type AuthorizationServer struct {
	http.ServeMux

	origin string
	rpID   string

	clientSecretKey []byte

	codeCache *codeCache

	config *OpenidConfiguration

	sessionStore *sessions.CookieStore
}

// TODO because we are dynamic we must support implict and code grant
func New(rpID string, origin string, privateECDSAKey *ecdsa.PrivateKey, privateRSAKey *rsa.PrivateKey, cookieKeys [][]byte, clientSecretKey []byte) AuthorizationServer {
	server := AuthorizationServer{}
	server.rpID = rpID
	server.origin = origin
	server.clientSecretKey = clientSecretKey

	sessionStore := sessions.NewCookieStore(cookieKeys...)
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = true
	server.sessionStore = sessionStore

	privateECDSAJWK := jose.JSONWebKey{
		Key:       privateECDSAKey,
		KeyID:     string(jose.ES256),
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	privateRSAJWK := jose.JSONWebKey{
		Key:       privateRSAKey,
		KeyID:     string(jose.RS256),
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	privateJWKS := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{privateECDSAJWK, privateRSAJWK},
	}

	publicJWKs := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{privateECDSAJWK.Public(), privateRSAJWK.Public()},
	}

	server.config = &OpenidConfiguration{
		Issuer:                            origin,
		RegistrationEndpoint:              origin + register,
		AuthEndpoint:                      origin + authorize,
		TokenEndpoint:                     origin + token,
		JWKSURI:                           origin + wellKnownJwks,
		UserinfoEndpoint:                  origin + userinfo,
		SupportedAlgs:                     []jose.SignatureAlgorithm{jose.ES256, jose.RS256},
		SupportedScopes:                   []string{"openid"},
		SubjectTypesSupported:             []string{"pairwise"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ACRValuesSupported:                []protocol.ConveyancePreference{},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
	}

	server.Handle(openidConfiguration, http.HandlerFunc(server.handleOpenidConfiguration))
	server.Handle(oauthAuthorizationServer, http.HandlerFunc(server.handleOpenidConfiguration))
	server.Handle(authorize, http.HandlerFunc(server.handleAuthorize))
	server.Handle(token, &TokenResource{
		origin:      origin,
		codeCache:   newCodeCache(),
		privateJWKs: privateJWKS,
	})
	server.Handle(wellKnownJwks, &JWKSResource{
		publicJWKS: publicJWKs,
	})
	server.Handle(register, &RegistrationResource{
		clientSecretKey: clientSecretKey,
	})
	server.Handle(userinfo, &UserInfoResource{
		accessTokenPublicJWKs: publicJWKs,
	})

	return server
}

type JWKSResource struct {
	publicJWKS jose.JSONWebKeySet
}

func (r *JWKSResource) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(r.publicJWKS)
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
