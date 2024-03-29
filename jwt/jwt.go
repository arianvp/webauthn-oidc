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
	header := &header{
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

	toSign := headerB64 + "." + claimsB64
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
	signature := make([]byte, keyBytes*2)
	r.FillBytes(signature[:keyBytes])
	s.FillBytes(signature[keyBytes:])
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return toSign + "." + signatureB64, nil

}

func DecodeAndVerify(jwt string, payload interface{}, getPublicKey func(keyID string) (*ecdsa.PublicKey, error)) error {
	parts := strings.Split(jwt, ".")
	if len(parts) < 3 {
		return errors.New("jwt: invalid token received")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return err
	}

	if h.Typ != "JWT" {
		return fmt.Errorf("jwt: Unexpected type: %s", h.Typ)
	}

	if h.Algorithm != "ES256" {
		return fmt.Errorf("jwt: Unsupported algorithm: %s", h.Algorithm)
	}

	publicKey, err := getPublicKey(h.KeyID)
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

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	if err := json.Unmarshal(payloadBytes, payload); err != nil {
		return err
	}
	return nil
}
