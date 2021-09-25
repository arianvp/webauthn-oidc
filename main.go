package main

import (
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/oauthclient"
)

func main() {
	oauthclient := oauthclient.New()
	oauthClientHttpServer := http.Server{Handler: &oauthclient, Addr: "[::]:8080"}
	log.Fatal(oauthClientHttpServer.ListenAndServe())
}
