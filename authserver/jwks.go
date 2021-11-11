package authserver

import (
	"encoding/json"
	"net/http"

	"gopkg.in/square/go-jose.v2"
)

type JWKSResource struct {
	publicJWKS jose.JSONWebKeySet
}

func (r *JWKSResource) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(r.publicJWKS)
}
