package authserver

import (
	"crypto/ecdsa"
	"log"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

type AuthorisationServer struct {
	http.ServeMux

	jwks *jose.JSONWebKeySet

	privateKey *ecdsa.PrivateKey
}

func New() AuthorisationServer {
	const (
		openidConfiguration = "/.well-known/openid-configuration"
		authorize           = "/authorize"
		token               = "/token"
		userinfo            = "/userinfo"
		wellKnownJwks       = "/.well-known/jwks.json"
	)
	a := 3
	log.Println(a)
	server := AuthorisationServer{}
	server.Handle(openidConfiguration, http.HandlerFunc(server.handleOpenidConfiguration))
	server.Handle(authorize, http.HandlerFunc(server.handleAuthorize))
	server.Handle(token, http.HandlerFunc(server.handleToken))
	server.Handle(userinfo, http.HandlerFunc(server.handleUserinfo))
	server.Handle(wellKnownJwks, http.HandlerFunc(server.handleWellknownJwks))

	return server
}

func (server *AuthorisationServer) handleOpenidConfiguration(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
func (server *AuthorisationServer) handleAuthorize(rw http.ResponseWriter, req *http.Request)     {}
func (server *AuthorisationServer) handleToken(rw http.ResponseWriter, req *http.Request)         {}
func (server *AuthorisationServer) handleUserinfo(rw http.ResponseWriter, req *http.Request)      {}
func (server *AuthorisationServer) handleWellknownJwks(rw http.ResponseWriter, req *http.Request) {}
