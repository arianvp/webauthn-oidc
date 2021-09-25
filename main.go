package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	jwt "github.com/golang-jwt/jwt/v4"
)

var (
	sessionStore *session.Store
	privateKey   *ecdsa.PrivateKey
)

type Params struct {
	// oauth-specific
	responseType        string
	clientID            string
	redirectURI         string
	state               string
	scope               string
	nonce               string
	codeChallengeMethod string
	codeChallenge       string

	// Webauthn-specific
	challenge           string
	publicKeyCredential string
}

type User struct {
	credential webauthn.Credential
}

func New(credentialID, publicKey string) (*User, error) {
	id, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil {
		return nil, err
	}
	pky, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	return &User{
		credential: webauthn.Credential{
			ID:        id,
			PublicKey: pky,
		},
	}, nil
}
func (user *User) WebAuthnID() []byte {
	return []byte("wedonotreallycare")
}

func (user *User) WebAuthnName() string {
	return "Whatever"
}

func (user *User) WebAuthnDisplayName() string {
	return "New User"
}

func (user *User) WebAuthnIcon() string {
	return ""
}

func (user *User) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{user.credential}
}

type UserRegistration struct {
}

// this works as we use the CredentialID as the unique identifier
func (user *UserRegistration) WebAuthnID() []byte {
	return []byte("wedonotreallycare")
}

func (user *UserRegistration) WebAuthnName() string {
	return "Whatever"
}

func (user *UserRegistration) WebAuthnDisplayName() string {
	return "New User"
}

func (user *UserRegistration) WebAuthnIcon() string {
	return ""
}

func (user *UserRegistration) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{}
}

var webauthnHandler *webauthn.WebAuthn

func main() {
	var err error
	webauthnHandler, err = webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "Webauthn OIDC",
		RPOrigin:      "http://localhost:8080",
	})
	if err != nil {
		log.Fatal(err)
		return
	}
	sessionStore, err = session.NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("failed to create keyPair:", err)
	}
	http.HandleFunc("/", indexEndpoint)
	http.HandleFunc("/oauth2/auth", authEndpoint)
	http.HandleFunc("/oauth2/token", tokenEndpoint)
	http.HandleFunc("/callback", callbackEndpoint)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexEndpoint(rw http.ResponseWriter, req *http.Request) {
	t := template.New("index.html")
	t, err := t.ParseFiles("index.html")
	if err != nil {
		log.Fatal(err)
	}
	rw.Header().Set("Content-Type", "text/html")
	t.Execute(rw, nil)
}

type AuthorisationCodeClaims struct {
	jwt.StandardClaims
	CodeChallenge string `json:"code_challenge,omitempty"`
}

type Subject struct {
	PublicKey string `json:"pky"`
	ID        string `json:"cid"`
}

func (c AuthorisationCodeClaims) Valid() error {
	return c.StandardClaims.Valid()
}

func createAuthorisationCode(clientID string, credential *webauthn.Credential, codeChallenge string) (string, error) {
	subject, err := json.Marshal(
		Subject{
			ID:        base64.RawURLEncoding.EncodeToString(credential.ID),
			PublicKey: base64.RawURLEncoding.EncodeToString(credential.PublicKey),
		},
	)
	if err != nil {
		return "", err
	}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, AuthorisationCodeClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(10 * time.Second).Unix(),
			Audience:  clientID,
			Subject:   base64.RawURLEncoding.EncodeToString(subject),
		},
		CodeChallenge: codeChallenge,
	})
	return t.SignedString(privateKey)
}

func callbackEndpoint(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	resp, err := http.Post("http://localhost:8080/oauth2/token", "application/x-www-form-urlencoded", strings.NewReader(req.Form.Encode()))
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println(resp.Header)

	rw.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	rw.WriteHeader(200)
	_, err = io.Copy(rw, resp.Body)
	if err != nil {
		http.Error(rw, "lol", http.StatusBadRequest)
	}

}

// http://localhost:8080/oauth2/auth?response_type=code&client_id=0FaOBnoM0ROMfoJI5M1AUpIIpSRziSMwZrkpTPrQrGo&state=xyz&redirect_uri=http://localhost:8080/callback&code_challenge=6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY&code_challenge_method=S256
// http://localhost:8080/oauth2/auth?response_type=code&client_id=0FaOBnoM0ROMfoJI5M1AUpIIpSRziSMwZrkpTPrQrGo&state=xyz&redirect_uri=http://localhost:8080/callback&code_challenge=6fdkQaPm51l13DSukcAH3Mdx7_ntecHYd1vi3n0hMZY&code_challenge_method=S256

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "failed to parse form", http.StatusBadRequest)
		return
	}

	params := Params{
		responseType:        req.Form.Get("response_type"),
		clientID:            req.Form.Get("client_id"),
		redirectURI:         req.Form.Get("redirect_uri"),
		state:               req.Form.Get("state"),
		scope:               req.Form.Get("scope"),
		nonce:               req.Form.Get("nonce"),
		codeChallengeMethod: req.Form.Get("code_challenge_method"),
		codeChallenge:       req.Form.Get("code_challenge"),
		publicKeyCredential: req.Form.Get("public_key_credential"),
	}

	if params.redirectURI == "" {
		http.Error(rw, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	redirectURI_, err := url.Parse(params.redirectURI)

	if err != nil {
		http.Error(rw, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	responseQuery := redirectURI_.Query()

	// always set the state
	if params.state != "" {
		responseQuery.Set("state", params.state)
	}

	// no matter what, we redirect

	if params.responseType != "code" {
		responseQuery.Set("error", "unsupported_response_type")
		redirectURI_.RawQuery = responseQuery.Encode()
		http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
		return
	}
	if params.codeChallenge == "" {
		responseQuery.Set("error", "invalid_request")
		log.Println("Missing code challenge")
		redirectURI_.RawQuery = responseQuery.Encode()
		http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
		return
	}

	if params.codeChallengeMethod != "S256" {
		responseQuery.Set("error", "invalid_request")
		log.Println("Missing code challenge method")
		redirectURI_.RawQuery = responseQuery.Encode()
		http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
		return
	}

	sha256Sum := sha256.Sum256([]byte(params.redirectURI))
	expectedClientID := base64.RawURLEncoding.EncodeToString(sha256Sum[:])
	log.Printf(expectedClientID)
	if params.clientID != expectedClientID {
		log.Println("Unauthorized client")
		responseQuery.Set("error", "unauthorized_client")
		redirectURI_.RawQuery = responseQuery.Encode()
		http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
		return
	}

	if req.Method == http.MethodGet {

		// if there is no credential, we assume the user needs to register
		if params.publicKeyCredential == "" {
			// TODO call protocol directly
			user := UserRegistration{}
			opts, sessionData, err := webauthnHandler.BeginRegistration(&user, webauthn.WithConveyancePreference((protocol.PreferDirectAttestation)))
			if err != nil {
				responseQuery.Set("error", "invalid_request")
				log.Println(err)
				redirectURI_.RawQuery = responseQuery.Encode()
				http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
				return
			}
			err = sessionStore.SaveWebauthnSession("attestation", sessionData, req, rw)
			if err != nil {
				responseQuery.Set("error", "invalid_request")
				log.Println(err)
				redirectURI_.RawQuery = responseQuery.Encode()
				http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
				return
			}
			t := template.New("auth.html")
			t, err = t.ParseFiles("auth.html")
			if err != nil {
				log.Fatal(err)
			}
			rw.Header().Set("Content-Type", "text/html")
			err = t.Execute(rw, &opts)
			if err != nil {
				log.Fatal(err)
			}
			return

		}

	}

	if req.Method == http.MethodPost {
		sessionData, err := sessionStore.GetWebauthnSession("attestation", req)
		if err != nil {
			log.Println(err)
			responseQuery.Set("error", "invalid_request")
			redirectURI_.RawQuery = responseQuery.Encode()
			http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
			return
		}
		user := UserRegistration{}

		parsedResponse, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(params.publicKeyCredential))
		if err != nil {
			log.Println(err)
			responseQuery.Set("error", "invalid_request")
			redirectURI_.RawQuery = responseQuery.Encode()
			http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
			return
		}
		credential, err := webauthnHandler.CreateCredential(&user, sessionData, parsedResponse)
		if err != nil {
			err2 := err.(*protocol.Error)
			log.Println(err2.DevInfo)
			responseQuery.Set("error", "invalid_request")
			redirectURI_.RawQuery = responseQuery.Encode()
			http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
			return
		}

		// TODO  code needs to be temporary and redeem-once
		// TODO: Make the code a JWT containing all the information that we sign,
		// authenticated with a secret o make it opaque. That way we do not have to store any state

		code, err := createAuthorisationCode(expectedClientID, credential, params.codeChallenge)
		if err != nil {
			log.Println(err)
			responseQuery.Set("error", "invalid_request")
			redirectURI_.RawQuery = responseQuery.Encode()
			http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
			return
		}
		responseQuery.Set("code", code)
		redirectURI_.RawQuery = responseQuery.Encode()
		http.Redirect(rw, req, redirectURI_.String(), http.StatusFound)
	}
}

type TokenResponse struct {
	IDToken   string `json:"id_token"`
	TokenType string `json:"token_type"`
}

func tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(rw, "invalid body", http.StatusBadRequest)
		return
	}
	// grantType := req.PostForm.Get("authorization_grant")
	code := req.PostForm.Get("code")
	/*codeVerifier := req.PostForm.Get("code_verifier")
	hash := sha256.Sum256([]byte(codeVerifier))
	expectedCodeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])*/

	// hash, err := hex.DecodeString(codeVerifier)

	t, err := jwt.ParseWithClaims(code, &AuthorisationCodeClaims{}, func(t *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})

	if err != nil {

		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	claims := t.Claims.(*AuthorisationCodeClaims)

	/*if expectedCodeChallenge != claims.CodeChallenge {
		http.Error(rw, "code_challenge mismatch", http.StatusBadRequest)
		return
	}*/
	claims.CodeChallenge = ""
	// ID token is much more valid
	claims.StandardClaims.ExpiresAt = time.Now().Add(24 * time.Hour).Unix()

	t = jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	idToken, err := t.SignedString(privateKey)

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(200)
	json.NewEncoder(rw).Encode(TokenResponse{IDToken: idToken, TokenType: "Bearer"})

}

func handleLogin(rw http.ResponseWriter, req *http.Request) {

}
