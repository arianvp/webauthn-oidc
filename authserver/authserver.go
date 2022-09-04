package authserver

import (
	"crypto/ecdsa"
	"embed"
	"net/http"

	"cloud.google.com/go/firestore"
	scsfs "github.com/alexedwards/scs/firestore"
	"github.com/alexedwards/scs/v2"
	"github.com/arianvp/webauthn-oidc/jwk"
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
func New(rpID string, origin string, privateECDSAKey *ecdsa.PrivateKey, clientSecretKey []byte, firesstoreClient *firestore.Client) AuthorizationServer {
	server := AuthorizationServer{}

	codeCache := newCodeCache()

	publicJWKs := jwk.JWKSet{
		Keys: []jwk.JWK{
			jwk.New("key", privateECDSAKey.PublicKey),
		},
	}

	supportedAlgs := []string{"ES256"}

	sessionManager := scs.New()
	if firesstoreClient != nil {
		sessionManager.Store = scsfs.New(firesstoreClient)
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
	server.Handle(authorize, sessionManager.LoadAndSave(&AuthorizeResource{
		rpID:           rpID,
		origin:         origin,
		sessionManager: sessionManager,
		codeCache:      codeCache,
	}))
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
