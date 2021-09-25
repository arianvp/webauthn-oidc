package authserver

import (
	"net/http"
	"net/url"

	"github.com/arianvp/webauthn-oidc/util"
	"github.com/ory/fosite"
)

type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallengeMethod string
	CodeChallenge       string
	Nonce               string
}

func AuthorizeRequestFromValues(values url.Values) AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        values.Get("response_type"),
		ClientID:            values.Get("client_id"),
		RedirectURI:         values.Get("redirect_uri"),
		State:               values.Get("state"),
		Scope:               values.Get("scope"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
		CodeChallenge:       values.Get("code_challenge"),
		Nonce:               values.Get("nonce"),
	}
}

type AuthorizeResponse struct {
	RedirectURI *url.URL
	State       string
	Error       *fosite.RFC6749Error
	Code        string
}

func (response *AuthorizeResponse) Values() url.Values {
	values := make(url.Values)
	values.Set("state", response.State)
	if response.Error != nil {
		for k, v := range response.Error.ToValues() {
			values[k] = v
		}
	} else {
		values.Set("code", response.Code)
	}
	return values
}

func (response *AuthorizeResponse) Respond(w http.ResponseWriter, req *http.Request) {
	response.RedirectURI.RawQuery = response.Values().Encode()
	w.Header().Add("Content-Type", "application/x-www-form-urlencoded")
	http.Redirect(w, req, response.RedirectURI.String(), http.StatusFound)
}

func (server *AuthorisationServer) handleAuthorize(w http.ResponseWriter, req *http.Request) {
	authorizeRequest := AuthorizeRequestFromValues(req.URL.Query())
	authorizeResponse := AuthorizeResponse{
		State: authorizeRequest.State,
	}

	if authorizeRequest.RedirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	if authorizeRequest.RedirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	redirectURI, err := url.Parse(authorizeRequest.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	authorizeResponse.RedirectURI = redirectURI

	expectedClientID := util.RegisterClient(authorizeRequest.RedirectURI)

	if authorizeRequest.ClientID != expectedClientID {
		authorizeResponse.Error = fosite.ErrInvalidRequest
		authorizeResponse.Respond(w, req)
		return
	}

	code, err := server.codeCache.newCode(&state{
		codeChallenge:       authorizeRequest.CodeChallenge,
		codeChallengeMethod: authorizeRequest.CodeChallengeMethod,
		redirectURI:         authorizeRequest.RedirectURI,
		clientID:            authorizeRequest.ClientID,
		nonce:               authorizeRequest.Nonce,
	})
	if err != nil {
		authorizeResponse.Error = fosite.ErrServerError
		authorizeResponse.Respond(w, req)
	}
	authorizeResponse.Code = code
	authorizeResponse.Respond(w, req)
}
