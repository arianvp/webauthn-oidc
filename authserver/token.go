package authserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
	"gopkg.in/square/go-jose.v2/jwt"
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
	Nonce  string `json:"nonce"`
	AtHash string `json:"at_hash"`
	CHash  string `json:"c_hash"`
	AMR    []AMR  `json:"amr"`
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
		ErrInvalidState.RespondJSON(w)
		return
	}

	authorized := false

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
		authorized = true
	}

	clientID, clientSecret, hasBasicAuth := req.BasicAuth()

	if err != nil {
		ErrInvalidRequest.WithDescription(err.Error()).RespondJSON(w)
		return
	}

	if hasBasicAuth && clientID == state.clientID && clientSecret == state.clientSecret {
		authorized = true
	}

	if !authorized {
		ErrUnauthorizedClient.WithDescription(fmt.Sprintf("%v %s==%s %s==%s", hasBasicAuth, clientID, state.clientID, clientSecret, state.clientSecret)).RespondJSON(w)
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
	expiresIn := jwt.NewNumericDate(now.Add(24 * time.Hour))

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

	claims := jwt.Claims{
		Issuer:    server.origin,
		Subject:   subject,
		Audience:  []string{server.origin},
		Expiry:    expiresIn,
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
		Expiry:    expiresIn,
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	}

	openIDClaims := OpenIDClaims{
		Nonce:  state.nonce,
		AtHash: atHash,
		CHash:  cHash,
		// TODO populate based on attestation
		AMR: []AMR{HardwareKey, MultiFactor},
	}

	idToken, err := jwt.Signed(signer).Claims(claims).Claims(openIDClaims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	tokenResponse := TokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	}

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse)

}
