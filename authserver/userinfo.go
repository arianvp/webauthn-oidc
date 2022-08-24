package authserver

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/arianvp/webauthn-oidc/jwk"
	"github.com/arianvp/webauthn-oidc/jwt"
)

type UserInfoResource struct {
	accessTokenPublicJWKs jwk.JWKSet
}

type UserinfoResponse struct {
	Subject string `json:"sub"`
}

func (r *UserInfoResource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	bearer := strings.Split(req.Header.Get("Authorization"), "Bearer ")
	if len(bearer) != 2 {
		ErrRequestUnauthorized.RespondJSON(w)
		return
	}
	var claims jwt.ClaimSet
	err := jwt.DecodeAndVerify(bearer[1], func(keyID string) (*ecdsa.PublicKey, error) {
		pubKey, err := r.accessTokenPublicJWKs.Get(keyID)
		if err != nil {
			return nil, err
		}
		return pubKey.GetPublicKey()
	}, token)
	if err != nil {
		ErrTokenSignatureMismatch.RespondJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserinfoResponse{claims.Subject})
}
