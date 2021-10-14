package authserver

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
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
	CodeChallenge       string `json:"code_challenge,omitempty"`
	Nonce               string `json:"nonce,omitempty"`
	MaxAge              string `json:"max_age,omitempty"`
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
		MaxAge:              values.Get("max_age"),
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
		Challenge   protocol.Challenge
		ClientID    string
		RedirectURI string
	}{challenge, authorizeRequest.ClientID, authorizeRequest.RedirectURI}); err != nil {
		panic(err)
	}
}

func FinishAuthenticate(challenge string, authorizeRequest AuthorizeRequest, redirectURI *url.URL, query url.Values, rpID, origin string) (*webauthn.Credential, *RFC6749Error) {
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

	expectedClientID := GenerateClientID(authorizeRequest.RedirectURI)
	if authorizeRequest.ClientID != expectedClientID {
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

	loginSession, err := server.sessionStore.Get(req, "loginSession")
	if err != nil {
		log.Println(err.Error())
	}
	var maxAge int64
	if authorizeRequest.MaxAge != "" {
		// TODO push parsing logic to the FromValues function
		maxAge, err = strconv.ParseInt(authorizeRequest.MaxAge, 10, 32)
		if err != nil {
			ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
		}
		loginSession.Options.MaxAge = int(maxAge)
	}
	loginSession.Options.SameSite = http.SameSiteLaxMode
	challengeSession, err := server.sessionStore.Get(req, "challengeSession")
	challengeSession.Options.SameSite = http.SameSiteStrictMode
	challengeSession.Options.MaxAge = 0

	var credential *webauthn.Credential = new(webauthn.Credential)
	rawCredential, ok := loginSession.Values["credential"].([]byte)
	if !ok {
		credential = nil
	} else {
		if err := json.Unmarshal(rawCredential, credential); err != nil {
			ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
			return
		}
	}

	authTime, _ := loginSession.Values["auth_time"].(int64)
	now := time.Now().Unix()

	// Expired
	if authTime+maxAge <= now {
		credential = nil
	}

	if credential == nil && authorizeRequest.Prompt == "none" {
		ErrInteractionRequired.RespondRedirect(w, redirectURI, query)
		return
	}

	if credential != nil && authorizeRequest.Prompt == "login" {
		credential = nil
	}

	if credential == nil {
		switch req.Method {
		case http.MethodGet:
			BeginAuthenticate(w, req, challengeSession, authorizeRequest, redirectURI, query)
		case http.MethodPost:
			challenge, ok := challengeSession.Values["challenge"].(string)
			if !ok {
				ErrInvalidRequest.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
				return
			}
			var oauthError *RFC6749Error
			credential, oauthError = FinishAuthenticate(challenge, authorizeRequest, redirectURI, query, server.rpID, server.origin)
			if oauthError != nil {
				oauthError.RespondRedirect(w, redirectURI, query)
				return
			}
			loginSession.Values["credential"], err = json.Marshal(credential)
			authTime = time.Now().Unix()
			loginSession.Values["auth_time"] = authTime

			if err != nil {
				ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	if err := loginSession.Save(req, w); err != nil {
		ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
		return
	}

	if authorizeRequest.CodeChallengeMethod != "S256" {
		ErrInvalidRequest.WithDescription("only S256 is supported.").RespondRedirect(w, redirectURI, query)
		return
	}

	code, err := server.codeCache.newCode(&state{
		codeChallenge: authorizeRequest.CodeChallenge,
		redirectURI:   authorizeRequest.RedirectURI,
		nonce:         authorizeRequest.Nonce,
		credential:    credential,
		authTime:      authTime,
	})
	if err != nil {
		ErrServerError.WithDescription(err.Error()).RespondRedirect(w, redirectURI, query)
		return
	}
	query.Set("code", code)
	redirectURI.RawQuery = query.Encode()
	w.Header().Set("Location", redirectURI.String())
	w.WriteHeader(http.StatusFound)
}
