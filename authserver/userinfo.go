package authserver

import (
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2/json"
	"gopkg.in/square/go-jose.v2/jwt"
)

func (server *AuthorizationServer) handleUserinfo(w http.ResponseWriter, req *http.Request) {
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

	for _, key := range server.publicJWKs.Keys {
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
	json.NewEncoder(w).Encode(claims)
}
