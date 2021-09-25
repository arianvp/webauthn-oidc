package main

import (
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/oauthclient"
)

func main() {
	// TODO replace with our oidc server
	oauthclient := oauthclient.New("https://wire.okta.com", "localhost")
	oauthClientHttpServer := http.Server{Handler: &oauthclient, Addr: "[::]:8080"}
	log.Fatal(oauthClientHttpServer.ListenAndServe())
}
