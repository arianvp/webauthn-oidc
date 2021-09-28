package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/arianvp/webauthn-oidc/authserver"
)

var (
	rpID     = flag.String("relying-party-id", "localhost", "Relying Party ID")
	origin   = flag.String("origin", "https://localhost:8443", "Origin")
	port     = flag.String("port", "8443", "Port number")
	certFile = flag.String("cert-file", "localhost.pem", "Certificate file")
	keyFile  = flag.String("key-file", "localhost-key.pem", "Key file")
	noTLS    = flag.Bool("no-tls", false, "Disable tls")
)

func main() {
	flag.Parse()

	authserver, err := authserver.New(*rpID, *origin)
	if err != nil {
		log.Fatal(err)
	}

	if *noTLS {
		log.Fatal(http.ListenAndServe("[::]:"+*port, authserver))
	} else {
		log.Fatal(http.ListenAndServeTLS("[::]:"+*port, *certFile, *keyFile, authserver))
	}

        // test

	/*oauthclient, err := oauthclient.New(serverOrigin, clientID, redirectURI)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe("[::]:"+clientPort, oauthclient))*/
}
