package authserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/arianvp/webauthn-oidc/util"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
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

func (server *AuthorizationServer) handleAuthorize(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		ErrInvalidRequest.WithDescription("invalid syntax").RespondJSON(w)
		return
	}
	authorizeRequest := AuthorizeRequestFromValues(req.Form)

	if authorizeRequest.RedirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		ErrInvalidRequest.WithDescription("missing redirect_uri").RespondJSON(w)
		return
	}

	redirectURI, err := url.Parse(authorizeRequest.RedirectURI)
	if err != nil {
		ErrInvalidRedirectURI.RespondJSON(w)
		return
	}

	query := redirectURI.Query()
	query.Set("state", authorizeRequest.State)

	expectedClientID, err := util.RegisterClient([]*url.URL{redirectURI})
	if err != nil {
		ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
	}

	if authorizeRequest.ClientID != expectedClientID {
		ErrInvalidRequest.WithDescription("redirect_uri does not match client_id.").RespondRedirect(w, redirectURI, query)
		return
	}

	session, err := server.sessionStore.Get(req, "webauthn")
	if err != nil {
		ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
		return
	}

	switch req.Method {
	case http.MethodGet:
		challenge, err := protocol.CreateChallenge()
		if err != nil {
			ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
		}

		serialized, _ := json.Marshal(&webauthn.SessionData{
			Challenge: challenge.String(),
		})

		session.Values["assertion"] = serialized
		if err := session.Save(req, w); err != nil {
			ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
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
		var sessionData webauthn.SessionData
		if err := json.Unmarshal(session.Values["assertion"].([]byte), &sessionData); err != nil {
			ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
		}
		// If both attestation and assertion are present

		if authorizeRequest.AssertionResponse == "" {
			ErrInvalidRequest.WithDescription("Assertion missing").RespondRedirect(w, redirectURI, query)
			return
		}

		if authorizeRequest.AttestationResponse == "" {
			ErrInvalidRequest.WithDescription("Attestation missing").RespondRedirect(w, redirectURI, query)
			return
		}

		var (
			attestationResponse *protocol.ParsedCredentialCreationData
			assertionResponse   *protocol.ParsedCredentialAssertionData
		)

		attestationResponse, err = protocol.ParseCredentialCreationResponseBody(strings.NewReader(authorizeRequest.AttestationResponse))
		if err != nil {
			ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
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
		// _ = attestationResponse.Verify(sessionData.Challenge, false, server.rpID, server.origin)

		// credential, err := server.(sessionData, attestationResponse)
		credential, err := webauthn.MakeNewCredential(attestationResponse)
		if err != nil {
			ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
		}

		assertionResponse, err = protocol.ParseCredentialRequestResponseBody(strings.NewReader(authorizeRequest.AssertionResponse))
		if err != nil {
			ErrInvalidRequest.WithDescription("Invalid assertion").RespondRedirect(w, redirectURI, query)
			return
		}

		if !bytes.Equal(credential.ID, assertionResponse.RawID) {
			ErrInvalidRequest.WithDescription("Unknown credential id").RespondRedirect(w, redirectURI, query)
			return
		}

		// TODO Relying Party ID
		if err := assertionResponse.Verify(sessionData.Challenge, server.rpID, server.origin, false, credential.PublicKey); err != nil {
			ErrRequestUnauthorized.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
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
			ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
		}
		query.Set("code", code)
		redirectURI.RawQuery = query.Encode()
		w.Header().Set("Location", redirectURI.String())
		w.WriteHeader(http.StatusFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
