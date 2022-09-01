package authserver

import (
	"encoding/json"
	"net/http"

	"github.com/arianvp/webauthn-oidc/jwk"
)

type JWKSResource struct {
	publicJWKS jwk.JWKSet
}

func (r *JWKSResource) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(r.publicJWKS)
}
