package authserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"gopkg.in/square/go-jose.v2/jwt"
)

type TokenRequest struct {
	Code         string // a time-bound use-once code
	CodeVerifier string // must check with previous code_challenge in authorize step
	GrantType    string // must check with previous redirect_uri in authorize step
	RedirectURI  string // must check with previous client_id in authorize stestirng
	ClientID     string
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
	}
}

func ParseTokenRequest(req *http.Request) (*TokenRequest, error) {
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	tokenRequest := TokenRequestFromValues(req.Form)
	return &tokenRequest, nil

}

func (server *AuthorizationServer) handleToken(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	tokenRequest, err := ParseTokenRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state := server.codeCache.del(tokenRequest.Code)
	if state == nil {
		ErrInvalidGrant.RespondJSON(w)
		return
	}

	if tokenRequest.CodeVerifier != "" {
		verifier := codeVerifier{
			challenge: state.codeChallenge,
			verifier:  tokenRequest.CodeVerifier,
			method:    state.codeChallengeMethod,
		}

		if err := verifier.Verify(); err != nil {
			// TODO is this the correct reponse?
			ErrInvalidRequest.WithDescription(err.Error()).RespondJSON(w)
			return
		}
	}
	clientID, clientSecret, hasBasicAuth := req.BasicAuth()

	if !hasBasicAuth {
		clientID = req.Form.Get("client_id")
		clientSecret = req.Form.Get("client_secret")
	}

	if clientID != "" && clientSecret != "" && (clientID != state.clientID || clientSecret != state.clientSecret) {
		ErrUnauthorizedClient.RespondJSON(w)
		return
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       server.privateJWKs.Key(string(jose.RS256))[0],
	}, &jose.SignerOptions{})

	if err != nil {
		panic(err)
	}

	now := time.Now()

	hasher := sha256.New()
	hasher.Write(state.credential.ID)
	hasher.Write(state.credential.PublicKey)
	hasher.Write([]byte(state.clientID))
	// NOTE: only taking 160 bits makes the subject a bit more readable while still
	// being plenty collision resistant
	subject := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)[:20])

	rawJTI := make([]byte, 32)
	if _, err := rand.Read(rawJTI); err != nil {
		panic(err)
	}

	jti := base64.RawURLEncoding.EncodeToString(rawJTI)

	accessTokenEpiresIn := jwt.NewNumericDate(now.Add(10 * time.Minute))

	claims := jwt.Claims{
		Issuer:    server.origin,
		Subject:   subject,
		Audience:  []string{server.origin},
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
		Issuer:    server.origin,
		Subject:   subject,
		Audience:  []string{state.clientID},
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

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)

}
