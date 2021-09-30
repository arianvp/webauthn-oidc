package authserver

import "net/http"

func (server *AuthorizationServer) handleUserinfo(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
