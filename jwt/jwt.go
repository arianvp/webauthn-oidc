package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type header struct {
	// The algorithm used for signature.
	Algorithm string `json:"alg"`
	// Represents the token type.
	Typ string `json:"typ"`
	// The hint which key is being used.  ID Tokens SHOULD NOT use the JWS or
	// JWE x5u, x5c, jku, or jwk Header Parameter fields. Instead, references to
	// keys used are communicated in advance using Discovery and Registration
	// parameters, per Section 10.
	KeyID string `json:"kid"`
}

type ClaimSet struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Expiry    int64    `json:"exp,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	JwtId     string   `json:"jti,omitempty"`
}

func EncodeAndSign(claims interface{}, keyID string, privateKey *ecdsa.PrivateKey) (string, error) {
	header := header{
		Algorithm: "ES256",
		Typ:       "JWT",
		KeyID:     keyID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	toSign := strings.Join([]string{headerB64, claimsB64}, ".")
	hash := sha256.Sum256([]byte(toSign))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}
	curveBits := privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	signature := append(rBytesPadded, sBytesPadded...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return strings.Join([]string{headerB64, claimsB64, signatureB64}, "."), nil

}

func DecodeAndVerify(jwt string, claims interface{}, getPublicKey func(keyID string) (*ecdsa.PublicKey, error)) error {
	parts := strings.Split(jwt, ".")
	if len(parts) < 3 {
		return errors.New("jwt: invalid token received")
	}
	h, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var h2 header
	if err := json.Unmarshal(h, &h2); err != nil {
		return err
	}
	if h2.Typ != "JWT" {
		return fmt.Errorf("jwt: Unexpected type: %s", h2.Typ)
	}
	if h2.Algorithm != "ES256" {
		return fmt.Errorf("jwt: Unsupported algorithm: %s", h2.Algorithm)
	}
	publicKey, err := getPublicKey(h2.KeyID)
	if err != nil {
		return err
	}
	c, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	toSign := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(toSign))
	curveBits := publicKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}
	r := new(big.Int).SetBytes(signature[:keyBytes])
	s := new(big.Int).SetBytes(signature[keyBytes:])
	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("jwt: invalid signature")
	}
	if err := json.Unmarshal(c, claims); err != nil {
		return err
	}
	return nil
}
