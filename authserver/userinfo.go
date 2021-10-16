package authserver

import (
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"gopkg.in/square/go-jose.v2/jwt"
)

type UserInfoResource struct {
	accessTokenPublicJWKs jose.JSONWebKeySet
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
	token, err := jwt.ParseSigned(bearer[1])
	if err != nil {
		ErrInvalidTokenFormat.RespondJSON(w)
		return
	}
	var claims jwt.Claims

	for _, key := range r.accessTokenPublicJWKs.Keys {
		err = token.Claims(key, &claims)
		if err == nil {
			break
		}
	}
	if err != nil {
		ErrTokenSignatureMismatch.RespondJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(UserinfoResponse{claims.Subject})
}
