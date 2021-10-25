package authserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"github.com/duo-labs/webauthn/webauthn"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"gopkg.in/square/go-jose.v2/jwt"
)

type TokenResource struct {
	origin          string
	codeCache       *codeCache
	privateJWKs     jose.JSONWebKeySet
	clientSecretKey []byte
}

type TokenRequest struct {
	Code         string // a time-bound use-once code
	CodeVerifier string // must check with previous code_challenge in authorize step
	GrantType    string // must check with previous redirect_uri in authorize step
	RedirectURI  string // must check with previous client_id in authorize stestirng
	ClientID     string
	ClientSecret string
}

type TokenResponse struct {
	AccessToken string           `json:"access_token,omitempty"`
	IDToken     string           `json:"id_token,omitempty"`
	TokenType   string           `json:"token_type,omitempty"`
	ExpiresIn   *jwt.NumericDate `json:"expires_in,omitempty"`
}

type AMR string

const (
	HardwareKey AMR = "hwk"
	SoftwareKey AMR = "swk"
	PIN         AMR = "pin"
	Fingerprint AMR = "fpt"
	MultiFactor AMR = "mfa"
)

type OpenIDClaims struct {
	Nonce    string          `json:"nonce,omitempty"`
	AtHash   string          `json:"at_hash"`
	CHash    string          `json:"c_hash,omitempty"`
	AMR      []AMR           `json:"amr,omitempty"`
	AuthTime jwt.NumericDate `json:"auth_time,omitempty"`
}

func TokenRequestFromValues(values url.Values) TokenRequest {
	return TokenRequest{
		Code:         values.Get("code"),
		CodeVerifier: values.Get("code_verifier"),
		GrantType:    values.Get("grant_type"),
		RedirectURI:  values.Get("redirect_uri"),
		ClientID:     values.Get("client_id"),
		ClientSecret: values.Get("client_secret"),
	}
}

func ParseTokenRequest(req *http.Request) TokenRequest {
	req.ParseForm()
	tokenRequest := TokenRequestFromValues(req.Form)
	clientID, clientSecret, hasBasicAuth := req.BasicAuth()
	if hasBasicAuth {
		// I think the presedence here is correct as client_id is only
		// required if BasicAuth is _not_ present
		// TODO read spec more closely
		tokenRequest.ClientID = clientID
		tokenRequest.ClientSecret = clientSecret
	}
	return tokenRequest
}

func makeSubject(credential webauthn.Credential, clientID string) string {

	hasher := sha256.New()
	hasher.Write(credential.ID)
	hasher.Write(credential.PublicKey)
	hasher.Write([]byte(clientID))
	// NOTE: only taking 160 bits makes the subject a bit more readable while still
	// being plenty collision resistant
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)[:20])
}

func (t *TokenResource) Handle(tokenRequest TokenRequest) (*TokenResponse, *RFC6749Error) {
	state := t.codeCache.del(tokenRequest.Code)
	if state == nil {
		return nil, ErrInvalidGrant
	}

	// if code_verifier is present, it must be valid to succeed
	if tokenRequest.CodeVerifier != "" {
		if err := VerifyCodeChallenge(state.codeChallenge, tokenRequest.CodeVerifier); err != nil {
			return nil, ErrInvalidRequest.WithDescription(err.Error())
		}
	}

	resp, err := RegisterClient(t.clientSecretKey, state.redirectURI)
	if err != nil {
		return nil, ErrInvalidRequest.WithDescription(err.Error())
	}

	if tokenRequest.ClientID != resp.ClientID {
		return nil, ErrUnauthorizedClient
	}

	authorized := false
	if tokenRequest.ClientSecret == "" && tokenRequest.CodeVerifier != "" {
		// public client
		authorized = true
	} else if tokenRequest.ClientSecret == resp.ClientSecret {
		// confidential client
		authorized = true
	}

	if !authorized {
		return nil, ErrUnauthorizedClient
	}

	signer, _ := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(t.privateJWKs.Keys[0].Algorithm),
		Key:       t.privateJWKs.Keys[0],
	}, &jose.SignerOptions{})

	now := time.Now()

	subject := makeSubject(*state.credential, tokenRequest.ClientID)

	rawJTI := make([]byte, 32)
	if _, err := rand.Read(rawJTI); err != nil {
		panic(err)
	}

	jti := base64.RawURLEncoding.EncodeToString(rawJTI)

	accessTokenEpiresIn := jwt.NewNumericDate(now.Add(10 * time.Minute))

	claims := jwt.Claims{
		Issuer:    t.origin,
		Subject:   subject,
		Audience:  []string{t.origin},
		Expiry:    accessTokenEpiresIn,
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	}

	accessToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	atHashRaw := sha256.Sum256([]byte(accessToken))
	atHash := base64.RawURLEncoding.EncodeToString(atHashRaw[:len(atHashRaw)/2])

	cHashRaw := sha256.Sum256([]byte(tokenRequest.Code))
	cHash := base64.RawURLEncoding.EncodeToString(cHashRaw[:len(atHashRaw)/2])

	rawJTI = make([]byte, 32)
	if _, err := rand.Read(rawJTI); err != nil {
		panic(err)
	}
	jti = base64.RawURLEncoding.EncodeToString(rawJTI)

	claims = jwt.Claims{
		Issuer:    t.origin,
		Subject:   subject,
		Audience:  []string{tokenRequest.ClientID},
		Expiry:    jwt.NewNumericDate(now.Add(10 * time.Hour)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	}

	openIDClaims := OpenIDClaims{
		Nonce:    state.nonce,
		AtHash:   atHash,
		CHash:    cHash,
		AMR:      []AMR{HardwareKey, MultiFactor},
		AuthTime: jwt.NumericDate(state.authTime),
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Claims(openIDClaims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	tokenResponse := TokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessTokenEpiresIn,
	}

	return &tokenResponse, nil
}

func (t *TokenResource) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tokenRequest := ParseTokenRequest(req)
	tokenResponse, err := t.Handle(tokenRequest)
	if err != nil {
		err.RespondJSON(w)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)
}
