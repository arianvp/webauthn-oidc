package authserver

import (
	"crypto/ecdsa"
	"embed"
	"net/http"

	"github.com/arianvp/webauthn-oidc/jwk"
	"github.com/arianvp/webauthn-oidc/session"
)

//go:embed *.html
var content embed.FS

const (
	openidConfigurationPath      = "/.well-known/openid-configuration"
	oauthAuthorizationServerPath = "/.well-known/oauth-authorization-server"
	register                     = "/register"
	authorize                    = "/authorize"
	token                        = "/token"
	userinfo                     = "/userinfo"
	wellKnownJwks                = "/.well-known/jwks.json"
	webFinger                    = "/.well-known/webfinger"
)

type AuthorizationServer struct {
	http.ServeMux
}

// TODO because we are dynamic we must support implict and code grant
func New(rpID string, origin string, privateECDSAKey *ecdsa.PrivateKey, cookieKeys [][]byte, clientSecretKey []byte, challengeSessionStore session.SessionStore[ChallengeSession], loginSessionStore session.SessionStore[LoginSession]) AuthorizationServer {
	server := AuthorizationServer{}

	codeCache := newCodeCache()

	publicJWKs := jwk.JWKSet{
		Keys: []jwk.JWK{jwk.New("key", privateECDSAKey.PublicKey)},
	}

	supportedAlgs := []string{"ES256"}

	openidConfiguration := OpenidConfiguration{
		Issuer:                            origin,
		RegistrationEndpoint:              origin + register,
		AuthEndpoint:                      origin + authorize,
		TokenEndpoint:                     origin + token,
		JWKSURI:                           origin + wellKnownJwks,
		UserinfoEndpoint:                  origin + userinfo,
		SupportedAlgs:                     supportedAlgs,
		SupportedScopes:                   []string{"openid"},
		SubjectTypesSupported:             []string{"pairwise"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ACRValuesSupported:                []string{},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
	}

	server.Handle(openidConfigurationPath, &openidConfiguration)
	server.Handle(oauthAuthorizationServerPath, &openidConfiguration)
	server.Handle(authorize, &AuthorizeResource{
		rpID:                  rpID,
		origin:                origin,
		challengeSessionStore: challengeSessionStore,
		loginSessionStore:     loginSessionStore,
		codeCache:             codeCache,
	})
	server.Handle(token, &TokenResource{
		origin:          origin,
		codeCache:       codeCache,
		privateKey:      privateECDSAKey,
		privateKeyId:    "key",
		clientSecretKey: clientSecretKey,
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
