package oauthclient

import (
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/util"
	"github.com/hashicorp/cap/oidc"
)

//go:embed *.html
var content embed.FS

type Client struct {
	http.ServeMux

	oidcProvider *oidc.Provider

	callback OauthCallback
	index    http.HandlerFunc

	redirectURI string
}

func New(issuer string, origin string) Client {
	supportedAlgs := []oidc.Alg{oidc.ES256}

	// Client IDs are the hash of the RedirectURI for webauthn-oidc
	redirectURI := fmt.Sprintf("http://%s/callback", origin)

	clientID := util.RegisterClient(redirectURI)

	allowedRedirectURIs := []string{redirectURI}

	oidcConfig, err := oidc.NewConfig(
		issuer, clientID, oidc.ClientSecret(""),
		supportedAlgs, allowedRedirectURIs,
	)

	provider, err := oidc.NewProvider(oidcConfig)
	if err != nil {
		log.Fatal(err)
	}

	client := Client{
		oidcProvider: provider,
		redirectURI:  redirectURI,
	}

	client.Handle("/", http.HandlerFunc(client.ServeIndex))
	client.Handle("/callback", &client.callback)
	return client
}
