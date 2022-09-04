package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"log"
	"net/http"

	"cloud.google.com/go/firestore"
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

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cookieKey := make([]byte, 64)
	_, err = rand.Reader.Read(cookieKey)
	if err != nil {
		log.Fatal(err)
	}
	clientSecretKey := make([]byte, 64)
	_, err = rand.Reader.Read(clientSecretKey)
	if err != nil {
		log.Fatal(err)
	}

	firestoreClient, err := firestore.NewClient(context.Background(), firestore.DetectProjectID)
	if err != nil {
		// If we cant detect firestore use in memory store
		firestoreClient = nil
	}

	authserver := authserver.New(*rpID, *origin, ecdsaKey, clientSecretKey, firestoreClient)
	if err != nil {
		log.Fatal(err)
	}

	if *noTLS {
		log.Fatal(http.ListenAndServe("[::]:"+*port, &authserver))
	} else {
		log.Fatal(http.ListenAndServeTLS("[::]:"+*port, *certFile, *keyFile, &authserver))
	}

	// test

	/*oauthclient, err := oauthclient.New(serverOrigin, clientID, redirectURI)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe("[::]:"+clientPort, oauthclient))*/
}
