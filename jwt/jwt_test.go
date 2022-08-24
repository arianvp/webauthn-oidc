package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const exampleKeyID = "0"
const exampleJWT = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjAifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.BA7YWMo9wzCEglpvthgqUmrEfDaWVbOGqx3ZqBs6Z0VwDA4TnM78R8QXz7G6Wonr6Vxo8VrkKToc63wQXdNfBA"
const examplePrivateKey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----
`

const examplePublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
`

func TestExampleJWTWorks(t *testing.T) {
	privateKeyBlock, _ := pem.Decode([]byte(examplePrivateKey))
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := privateKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("wat")
	}
	publicKeyBlock, _ := pem.Decode([]byte(examplePublicKey))
	publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := publicKeyAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("wat2")
	}

	if !privateKey.PublicKey.Equal(publicKey) {
		t.Fatal("Private key doesn't match public key")
	}

	claims := ClaimSet{}
	err = DecodeAndVerify(exampleJWT, func(keyID string) (*ecdsa.PublicKey, error) {
		if keyID == exampleKeyID {
			return publicKey, nil
		} else {
			return nil, errors.New("unkown public key")
		}
	}, &claims)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeAndVerify(t *testing.T) {
	claims := ClaimSet{}

	invalidJWT := "."
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail, %s", err)
	}

	invalidJWT = "%.."
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail")
	}

	invalidJWT = ".."
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail")
	}

	invalidJWT = ".%."
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail")
	}

	invalidJWT = "..%"
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail")
	}

	invalidHeader := header{
		Algorithm: "ES256",
		Typ:       "lol",
		KeyID:     "0",
	}
	headerBytes, _ := json.Marshal(invalidHeader)
	invalidHeaderb64 := base64.RawURLEncoding.EncodeToString(headerBytes)
	invalidJWT = invalidHeaderb64 + ".."
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail")
	}

	invalidHeader = header{
		Algorithm: "EX256",
		Typ:       "JWT",
		KeyID:     "0",
	}
	headerBytes, _ = json.Marshal(invalidHeader)
	invalidHeaderb64 = base64.RawURLEncoding.EncodeToString(headerBytes)
	invalidJWT = invalidHeaderb64 + ".."
	if err := DecodeAndVerify(invalidJWT, func(keyID string) (*ecdsa.PublicKey, error) { return nil, nil }, &claims); err == nil {
		t.Errorf("expected decode to fail")
	}

}

func FuzzRoundtripEncodeDecode(f *testing.F) {
	f.Add("a", "b", int64(0), int64(0), int64(0), "a", "b", "c", "d", "e", "f", "g", "h")
	f.Fuzz(func(t *testing.T, iss string, aud string, exp, auth_time, iat int64, typ, sub, nonce, acr, amr, azp, keyID string, alg string) {
		claims := ClaimSet{
			Issuer:   strings.ToValidUTF8(iss, ""),
			Subject:  strings.ToValidUTF8(sub, ""),
			Audience: []string{strings.ToValidUTF8(aud, "")},
			Expiry:   exp,
			IssuedAt: iat,
		}

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		jwt, err := EncodeAndSign(&claims, keyID, privateKey)
		if err != nil {
			t.Fatal(err)
		}

		fetchKey := func(keyID2 string) (*ecdsa.PublicKey, error) {
			if keyID == keyID2 {
				return &privateKey.PublicKey, nil
			} else {
				return nil, fmt.Errorf("unknown keyID: %s, expected %s", keyID2, keyID)
			}
		}

		claims2 := ClaimSet{}
		if err := DecodeAndVerify(jwt, fetchKey, &claims2); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(claims, claims2) {
			t.Fatalf("Claims didn't match, %v and %v", &claims, claims2)
		}

	})
}
