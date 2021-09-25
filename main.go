package main

import (
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/oauthclient"
)

func main() {
	oauthclient := oauthclient.New("https://wire.okta.com", "client.localhost")
	http.Handle("client.localhost/", &oauthclient)
	log.Fatal(http.ListenAndServe("[::]:8080", nil))
}
