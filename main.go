package main

import (
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/authserver"
	"github.com/arianvp/webauthn-oidc/oauthclient"
	"github.com/arianvp/webauthn-oidc/util"
)

func main() {
	serverPort := "8080"
	clientPort := "8081"
	serverOrigin := "http://localhost:" + serverPort
	clientOrigin := "http://localhost:" + clientPort
	redirectURI := clientOrigin + "/callback"

	clientID := util.RegisterClient(redirectURI)
	// clientID := "0oa1zzg4kiliCsqqW5d7"
	//serverOrigin := "https://dev-19105531.okta.com"

	authserver, err := authserver.New(serverOrigin)
	if err != nil {
		log.Fatal(err)
	}
	go http.ListenAndServe("[::]:"+serverPort, authserver)

	oauthclient, err := oauthclient.New(serverOrigin, clientID, redirectURI)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe("[::]:"+clientPort, oauthclient))
}
