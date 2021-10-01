package authserver

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/sessions"
)

type AuthorizeRequest struct {
	Request             string `json:"request,omitempty"`
	ResponseType        string `json:"response_type,omitempty"`
	ClientID            string `json:"client_id,omitempty"`
	RedirectURI         string `json:"redirect_uri,omitempty"`
	RequestURI          string `json:"request_uri,omitempty"`
	Prompt              string `json:"prompt,omitempty"`
	State               string `json:"state,omitempty"`
	Scope               string `json:"scope,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitmepty"`
	Nonce               string `json:"nonce,omitmepty"`
	AttestationResponse string `json:"attestation_response,omitempty"`
	AssertionResponse   string `json:"assertion_response,omitempty"`
}

func AuthorizeRequestFromValues(values url.Values) AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        values.Get("response_type"),
		ClientID:            values.Get("client_id"),
		RedirectURI:         values.Get("redirect_uri"),
		RequestURI:          values.Get("request_uri"),
		Request:             values.Get("request"),
		Prompt:              values.Get("prompt"),
		State:               values.Get("state"),
		Scope:               values.Get("scope"),
		CodeChallengeMethod: values.Get("code_challenge_method"),
		CodeChallenge:       values.Get("code_challenge"),
		Nonce:               values.Get("nonce"),
		AttestationResponse: values.Get("attestation_response"),
		AssertionResponse:   values.Get("assertion_response"),
	}
}

func BeginAuthenticate(w http.ResponseWriter, req *http.Request, session *sessions.Session, authorizeRequest AuthorizeRequest, redirectURI *url.URL, query url.Values) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
		return
	}

	session.Values["challenge"] = challenge.String()
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
}

func FinishAuthenticate(session *sessions.Session, authorizeRequest AuthorizeRequest, redirectURI *url.URL, query url.Values, rpID, origin string) (*webauthn.Credential, *RFC6749Error) {
	challenge := session.Values["challenge"].(string)
	// If both attestation and assertion are present

	if authorizeRequest.AssertionResponse == "" {
		return nil, ErrInvalidRequest.WithDescription("Assertion missing")
	}

	if authorizeRequest.AttestationResponse == "" {
		return nil, ErrInvalidRequest.WithDescription("Attestation missing")
	}

	var (
		attestationResponse *protocol.ParsedCredentialCreationData
		assertionResponse   *protocol.ParsedCredentialAssertionData
	)

	attestationResponse, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(authorizeRequest.AttestationResponse))
	if err != nil {
		return nil, ErrInvalidRequest.WithDescription(err.Error())
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
	// _ = attestationResponse.Verify(challenge, false, server.rpID, server.origin)

	// credential, err := server.(sessionData, attestationResponse)
	credential, err := webauthn.MakeNewCredential(attestationResponse)
	if err != nil {
		return nil, ErrInvalidRequest.WithDescription(err.Error())
	}

	assertionResponse, err = protocol.ParseCredentialRequestResponseBody(strings.NewReader(authorizeRequest.AssertionResponse))
	if err != nil {
		return nil, ErrInvalidRequest.WithDescription("Invalid assertion")
	}

	if !bytes.Equal(credential.ID, assertionResponse.RawID) {
		return nil, ErrInvalidRequest.WithDescription("Unknown credential id")
	}

	// TODO Relying Party ID
	if err := assertionResponse.Verify(challenge, rpID, origin, false, credential.PublicKey); err != nil {
		return nil, ErrRequestUnauthorized.WithDescription(err.Error())
	}
	return credential, nil

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

	registrationResponse, err := server.RegisterClient(RegistrationRequest{[]string{authorizeRequest.RedirectURI}})
	if err != nil {
		ErrInvalidRequest.WithDescription(err.Error()).RespondJSON(w)
		return
	}

	if authorizeRequest.ClientID != registrationResponse.ClientID {
		ErrInvalidRequest.WithDescription("redirect_uri does not match client_id.").RespondJSON(w)
		return
	}

	if authorizeRequest.RequestURI != "" {
		// TODO support.  need to decode the jwt at request_uri
		ErrRequestURINotSupported.RespondRedirect(w, redirectURI, query)
		return
	}
	if authorizeRequest.Request != "" {
		// TODO support
		ErrRequestNotSupported.RespondRedirect(w, redirectURI, query)
		return
	}
	if authorizeRequest.ResponseType != "code" {
		ErrUnsupportedResponseType.RespondRedirect(w, redirectURI, query)
		return
	}

	session, err := server.sessionStore.Get(req, "webauthn")
	if err != nil {
		// non-fatal. resets session
		log.Print(err)
	}

	// TODO check if usr logged in
	if authorizeRequest.Prompt == "none" {
		ErrInteractionRequired.RespondRedirect(w, redirectURI, query)
		return
	}

	switch req.Method {
	case http.MethodGet:
		BeginAuthenticate(w, req, session, authorizeRequest, redirectURI, query)
		return

	case http.MethodPost:
		credential, err := FinishAuthenticate(session, authorizeRequest, redirectURI, query, server.rpID, server.origin)
		if err != nil {
			err.RespondRedirect(w, redirectURI, query)
			return
		}

		now := time.Now()

		code, err2 := server.codeCache.newCode(&state{
			codeChallenge:       authorizeRequest.CodeChallenge,
			codeChallengeMethod: authorizeRequest.CodeChallengeMethod,
			redirectURI:         authorizeRequest.RedirectURI,
			clientID:            authorizeRequest.ClientID,
			clientSecret:        registrationResponse.ClientSecret,
			nonce:               authorizeRequest.Nonce,
			credential:          credential,
			authTime:            now,
		})

		if err2 != nil {
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
