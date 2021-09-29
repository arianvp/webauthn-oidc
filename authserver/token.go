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

	var tokenResponse TokenResponse
	state := server.codeCache.del(tokenRequest.Code)
	if state == nil {
		tokenResponse.Error = ErrInvalidRequest.ErrorField
		tokenResponse.ErrorDescription = ErrInvalidRequest.DescriptionField
		w.Header().Add("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}
	verifier := codeVerifier{
		challenge: state.codeChallenge,
		verifier:  tokenRequest.CodeVerifier,
		method:    state.codeChallengeMethod,
	}

	if err := verifier.Verify(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       server.privateKey,
	}, &jose.SignerOptions{})

	if err != nil {
		panic(err)
	}

	accessToken, err := jwt.Signed(signer).CompactSerialize()
	if err != nil {
		panic(err)
	}
	tokenResponse.AccessToken = accessToken

	atHashRaw := sha256.Sum256([]byte(accessToken))
	atHash := base64.RawURLEncoding.EncodeToString(atHashRaw[:len(atHashRaw)/2])

	cHashRaw := sha256.Sum256([]byte(tokenRequest.Code))
	cHash := base64.RawURLEncoding.EncodeToString(cHashRaw[:len(atHashRaw)/2])

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

	claims := jwt.Claims{
		Issuer:    server.origin,
		Subject:   subject,
		Audience:  []string{state.clientID},
		Expiry:    jwt.NewNumericDate(now.Add(24 * time.Hour)),
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
	tokenResponse.IDToken = idToken

	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokenResponse); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

}
