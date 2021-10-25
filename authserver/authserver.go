package authserver

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"embed"
	"net/http"

	"github.com/gorilla/sessions"
	"gopkg.in/square/go-jose.v2"
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
func New(rpID string, origin string, privateECDSAKey *ecdsa.PrivateKey, privateRSAKey *rsa.PrivateKey, cookieKeys [][]byte, clientSecretKey []byte) AuthorizationServer {
	server := AuthorizationServer{}

	codeCache := newCodeCache()

	sessionStore := sessions.NewCookieStore(cookieKeys...)
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = true

	privateECDSAJWK := jose.JSONWebKey{
		Key:       privateECDSAKey,
		KeyID:     string(jose.ES256),
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}

	//privateRSAJWK := jose.JSONWebKey{
	//	Key:       privateRSAKey,
	//	KeyID:     string(jose.RS256),
	//	Algorithm: string(jose.RS256),
	//	Use:       "sig",
	//}

	privateJWKS := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{privateECDSAJWK},
	}

	publicJWKs := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{privateECDSAJWK.Public()},
	}

	var supportedAlgs []jose.SignatureAlgorithm
	for _, v := range publicJWKs.Keys {
		supportedAlgs = append(supportedAlgs, jose.SignatureAlgorithm(v.Algorithm))
	}

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
		rpID:         rpID,
		origin:       origin,
		sessionStore: sessionStore,
		codeCache:    codeCache,
	})
	server.Handle(token, &TokenResource{
		origin:      origin,
		codeCache:   codeCache,
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
