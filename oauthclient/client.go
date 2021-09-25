package oauthclient

import (
	"embed"
	"net/http"

	"github.com/hashicorp/cap/oidc"
)

//go:embed *.html
var content embed.FS

type Client struct {
	http.ServeMux

	oidcProvider *oidc.Provider

	callback http.HandlerFunc
	index    http.HandlerFunc

	cache *requestCache

	redirectURI string
}

func New(issuer string, clientID string, redirectURI string) (*Client, error) {
	supportedAlgs := []oidc.Alg{oidc.ES256, oidc.RS256}

	allowedRedirectURIs := []string{redirectURI}

	oidcConfig, err := oidc.NewConfig(
		issuer, clientID, oidc.ClientSecret(""),
		supportedAlgs, allowedRedirectURIs,
	)
	if err != nil {
		return nil, err
	}

	provider, err := oidc.NewProvider(oidcConfig)
	if err != nil {
		return nil, err
	}

	client := Client{
		oidcProvider: provider,
		redirectURI:  redirectURI,
		cache:        newRequestCache(),
	}

	client.Handle("/", http.HandlerFunc(client.ServeIndex))
	client.Handle("/callback", http.HandlerFunc(client.ServeCallback))
	return &client, nil
}
