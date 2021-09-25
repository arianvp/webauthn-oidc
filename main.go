package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/oauthclient"
)

func main() {

	clientOrigin := "client.localhost:8080"
	redirectURI := fmt.Sprintf("http://%s/callback", clientOrigin)

	clientID := "0oa1zzg4kiliCsqqW5d7"

	authServer := "https://dev-19105531.okta.com"

	oauthclient := oauthclient.New(authServer, clientID, redirectURI)
	http.Handle("client.localhost/", &oauthclient)
	log.Fatal(http.ListenAndServe("[::]:8080", nil))
}
