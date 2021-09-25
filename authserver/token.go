package authserver

import (
	"net/http"
	"net/url"

	"github.com/ory/fosite"
	"gopkg.in/square/go-jose.v2/json"
)

type TokenRequest struct {
	// a time-bound use-once code
	Code string
	// must check with previous code_challenge in authorize step
	CodeVerifier string
	GrantType    string
	// must check with previous redirect_uri in authorize step
	RedirectURI string
	// must check with previous client_id in authorize stestirng
	ClientID string
}

type TokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        *int32 `json:"expires_in,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func TokenRequestFromValues(values url.Values) TokenRequest {
	return TokenRequest{
		Code:         values.Get("code"),
		CodeVerifier: values.Get("code_verifier"),
		GrantType:    values.Get("grant_type"),
		RedirectURI:  values.Get("redirect_uri"),
		ClientID:     values.Get("client_id"),
	}
}

func (server *AuthorizationServer) handleToken(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tokenRequest := TokenRequestFromValues(req.Form)
	var tokenResponse TokenResponse
	state := server.codeCache.del(tokenRequest.Code)
	if state == nil {
		tokenResponse.Error = fosite.ErrInvalidRequest.ErrorField
		tokenResponse.ErrorDescription = fosite.ErrInvalidRequest.DescriptionField
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

}
