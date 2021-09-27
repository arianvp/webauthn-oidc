package main

import (
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/authserver"
)

func main() {
	serverPort := "8443"
	rpID := "localhost"
	serverOrigin := "https://localhost:" + serverPort

	// clientPort := "8081"
	// clientOrigin := "http://localhost:" + clientPort
	// redirectURI := clientOrigin + "/callback"

	// clientID := util.RegisterClient(redirectURI)
	// clientID := "0oa1zzg4kiliCsqqW5d7"
	//serverOrigin := "https://dev-19105531.okta.com"

	authserver, err := authserver.New(rpID, serverOrigin)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(http.ListenAndServeTLS("[::]:"+serverPort, "./localhost.pem", "./localhost-key.pem", authserver))

	/*oauthclient, err := oauthclient.New(serverOrigin, clientID, redirectURI)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe("[::]:"+clientPort, oauthclient))*/
}
