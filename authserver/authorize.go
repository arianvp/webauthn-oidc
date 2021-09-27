package authserver

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/arianvp/webauthn-oidc/util"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
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
	AttestationResponse string
	AssertionResponse   string
}

type AuthorizeParams struct {
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
		AttestationResponse: values.Get("attestation_response"),
		AssertionResponse:   values.Get("assertion_response"),
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

func (server *AuthorizationServer) handleAuthorize(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "invalid data", http.StatusBadRequest)
		return
	}
	authorizeRequest := AuthorizeRequestFromValues(req.Form)
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
		authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription("redirect_uri does not match client_id.")
		authorizeResponse.Respond(w, req)
		return
	}

	switch req.Method {
	case http.MethodGet:
		challenge, err := protocol.CreateChallenge()
		if err != nil {
			authorizeResponse.Error = fosite.ErrServerError
			authorizeResponse.Respond(w, req)
		}
		err = server.sessionStore.SaveWebauthnSession("session", &webauthn.SessionData{
			Challenge: challenge.String(),
		}, req, w)
		if err != nil {
			authorizeResponse.Error = fosite.ErrServerError.WithDescription(err.Error())
			authorizeResponse.Respond(w, req)
		}

		template := template.New("authorize.html")
		template, err = template.ParseFS(content, "authorize.html")
		if err != nil {
			panic(err)
		}
		if err := template.Execute(w, struct {
			Challenge protocol.Challenge
			ClientID  string
		}{challenge, authorizeRequest.ClientID}); err != nil {
			panic(err)
		}

	case http.MethodPost:
		sessionData, err := server.sessionStore.GetWebauthnSession("session", req)
		if err != nil {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription(err.Error())
			authorizeResponse.Respond(w, req)
			return
		}

		// If both attestation and assertion are present

		if authorizeRequest.AssertionResponse == "" {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription("Assertion missing")
			authorizeResponse.Respond(w, req)
			return
		}

		if authorizeRequest.AttestationResponse == "" {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription("Attestation missing")
			authorizeResponse.Respond(w, req)
			return
		}

		var (
			attestationResponse *protocol.ParsedCredentialCreationData
			assertionResponse   *protocol.ParsedCredentialAssertionData
		)

		attestationResponse, err = protocol.ParseCredentialCreationResponseBody(strings.NewReader(authorizeRequest.AttestationResponse))
		if err != nil {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription(err.Error())
			authorizeResponse.Respond(w, req)
			return
		}

		// TODO: Only works if attestation response was created in the same step as
		// assertion What we could do is store an initial signed attestation in a
		// cookie.  This signature will be valid for a long period of time and
		// attests that we performed attestation.  This can then be presented to us
		// to  mint an ID token with attestation data. However; for now, we don't
		// "care", and accept anything. So ignore the result. This will require a
		// dedicated html page for registration that stores it into the cookie /
		// local storage. This is not needed for the MVP.
		// Explicit consent will be asked as attestation is "revealing"
		// user_verified depends on acr_values
		_ = attestationResponse.Verify(sessionData.Challenge, false, server.rpID, server.origin)

		// credential, err := server.(sessionData, attestationResponse)
		credential, err := webauthn.MakeNewCredential(attestationResponse)
		if err != nil {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription(err.Error())
			authorizeResponse.Respond(w, req)
			return
		}

		assertionResponse, err = protocol.ParseCredentialRequestResponseBody(strings.NewReader(authorizeRequest.AssertionResponse))
		if err != nil {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription("Invalid assertion")
			authorizeResponse.Respond(w, req)
			return
		}

		if !bytes.Equal(credential.ID, assertionResponse.RawID) {
			authorizeResponse.Error = fosite.ErrInvalidRequest.WithDescription("Unknown credential id")
			authorizeResponse.Respond(w, req)
			return
		}

		// TODO Relying Party ID
		if err := assertionResponse.Verify(sessionData.Challenge, server.rpID, server.origin, false, credential.PublicKey); err != nil {
			authorizeResponse.Error = fosite.ErrRequestUnauthorized.WithDescription(err.Error())
			authorizeResponse.Respond(w, req)
			return
		}

		code, err := server.codeCache.newCode(&state{
			codeChallenge:       authorizeRequest.CodeChallenge,
			codeChallengeMethod: authorizeRequest.CodeChallengeMethod,
			redirectURI:         authorizeRequest.RedirectURI,
			clientID:            authorizeRequest.ClientID,
			nonce:               authorizeRequest.Nonce,
			credential:          credential,
		})

		if err != nil {
			authorizeResponse.Error = fosite.ErrServerError
			authorizeResponse.Respond(w, req)
		}
		authorizeResponse.Code = code
		authorizeResponse.Respond(w, req)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
