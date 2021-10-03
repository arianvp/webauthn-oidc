// Provides a simplified webauthn implementation with no external dependencies.
// It  utilisies  the "Easily accessing credential data" features from the
// Webauthn L2 spec https://www.w3.org/TR/webauthn-2/#sctn-public-key-easy This
// removes the need for parsing the complicated attestation response in case no
// attestation is needed, greatly reducing the amount of dependencies and code
// needed to perform the webauthn legs
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

type AuthenticatorFlags byte

const (
	// FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
	FlagUserPresent AuthenticatorFlags = 1 << iota // Referred to as UP
	_                                              // Reserved
	// FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified
	// by the authenticator using a biometric or PIN
	FlagUserVerified // Referred to as UV
)

type AuthenticatorData struct {
	RPIDHash [32]byte
	Flags    AuthenticatorFlags
	Count    uint32
	// ignore other fields
}

func ReadAuthenticatorData(r io.Reader, data *AuthenticatorData) error {
	return binary.Read(r, binary.BigEndian, data)
}

func WriteAuthenticatorData(w io.Writer, data *AuthenticatorData) error {
	return binary.Write(w, binary.BigEndian, data)
}

// A simpl
type AuthenticatorResponse struct {
	ClientDataJSON []byte
	// In the case of AuthenticatorAttestationResponse this is the result of  the
	// getAuthenticatorData() call and in tcase of AuthenticatorAssertionResponse
	// this field is provided by the API directly
	AuthenticatorData []byte
}

type COSEAlgorithmIdentifier int32

const (
	ES256 COSEAlgorithmIdentifier = -7
	EdDSA COSEAlgorithmIdentifier = -8
	ES384 COSEAlgorithmIdentifier = -35
	ES512 COSEAlgorithmIdentifier = -36
	PS256 COSEAlgorithmIdentifier = -37
	RS256 COSEAlgorithmIdentifier = -257
)

type AuthenticatorAttestationResponse struct {
	AuthenticatorResponse
	// getTransports()
	transports []string
	// getPublicKey()
	PublicKey []byte
	// getPublicKeyAlgorithm
	PublicKeyAlgorithm COSEAlgorithmIdentifier
}

type TokenBindingStatus string

type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id"`
}

type ClientData struct {
	Type         string        `json:"type"`
	Challenge    string        `json:"challenge"`
	Origin       string        `json:"origin"`
	CrossOrigin  bool          `json:"crossOrigin"`
	TokenBinding *TokenBinding `json:"tokenBinding"`
}

type AuthenticatorAssertionResponse struct {
	AuthenticatorResponse
	Signature  []byte
	UserHandle []byte
}

// returned from navigator.credential.create({publicKey:{...}})
type CreatePublicKeyCredential struct {
	Type     string                           `json:"type"`
	Id       string                           `json:"id"`
	RawId    []byte                           `json:"rawId"`
	Response AuthenticatorAttestationResponse `json:"response"`
}

// returned from navigator.credential.get({publicKey:{...}})
type GetPublicKeyCredential struct {
	Type     string                         `json:"type"`
	Id       string                         `json:"id"`
	RawId    []byte                         `json:"rawId"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

func (r *AuthenticatorResponse) ParseClientData() (*ClientData, error) {
	var data ClientData
	err := json.Unmarshal(r.ClientDataJSON, &data)
	if err != nil {
		return nil, err
	}
	return &data, err
}

func (r *AuthenticatorAttestationResponse) ParsePublicKey() (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(r.PublicKey)
}

func (r *AuthenticatorAttestationResponse) ParseClientData() (*ClientData, error) {
	clientData, err := r.AuthenticatorResponse.ParseClientData()
	if err != nil {
		return nil, err
	}
	if clientData.Type != "webauthn.create" {
		return nil, errors.New("Invalid type. Expected webauthn.create")
	}
	return clientData, nil
}

func (r *AuthenticatorAssertionResponse) ParseClientData() (*ClientData, error) {
	clientData, err := r.AuthenticatorResponse.ParseClientData()
	if err != nil {
		return nil, err
	}
	if clientData.Type != "webauthn.get" {
		return nil, errors.New("Invalid type. Expected webauthn.get")
	}
	return clientData, nil
}

func (r *AuthenticatorResponse) Verify(typ, challenge, rpID, origin string, verifyUser bool) error {
	var clientData ClientData
	if err := json.Unmarshal(r.ClientDataJSON, &clientData); err != nil {
		return err
	}
	if clientData.Type != typ {
		return errors.New("type mismatch")
	}
	if clientData.Challenge != challenge {
		return errors.New("challenge mismatch")
	}
	if clientData.Origin != origin {
		return errors.New("origin mismatch")
	}
	var authentiatorData AuthenticatorData
	if err := ReadAuthenticatorData(bytes.NewReader(r.AuthenticatorData), &authentiatorData); err != nil {
		return err
	}
	if authentiatorData.RPIDHash != sha256.Sum256([]byte(rpID)) {
		return errors.New("rpID hash mismatch")
	}
	if verifyUser && authentiatorData.Flags&FlagUserVerified == 0 {
		return errors.New("user not verified")
	}
	return nil
}

func (attestation *AuthenticatorAttestationResponse) Verify(challenge, rpID, origin string, verifyUser bool) error {
	return attestation.AuthenticatorResponse.Verify("webauthn.create", challenge, rpID, origin, verifyUser)
}

func (assertion *AuthenticatorAssertionResponse) Verify(challenge, rpID, origin string, verifyUser bool, attestation *AuthenticatorAttestationResponse) error {
	if err := assertion.AuthenticatorResponse.Verify("webauthn.get", challenge, rpID, origin, verifyUser); err != nil {
		return err
	}
	publicKey, err := attestation.ParsePublicKey()
	if err != nil {
		return err
	}
	signed := append(assertion.AuthenticatorData, crypto.SHA256.New().Sum(assertion.ClientDataJSON)...)
	if err := checkSignature(attestation.PublicKeyAlgorithm, signed, assertion.Signature, publicKey); err != nil {
		return err
	}
	return nil
}

func (alg COSEAlgorithmIdentifier) Hash() crypto.Hash {
	switch alg {
	case ES256:
		return crypto.SHA256
	case PS256:
		return crypto.SHA256
	case RS256:
		return crypto.SHA256
	case EdDSA:
		return crypto.SHA256
	case ES384:
		return crypto.SHA384
	case ES512:
		return crypto.SHA512
	default:
		panic("should never happen")
	}
}

func checkSignature(alg COSEAlgorithmIdentifier, signed, signature []byte, publicKey crypto.PublicKey) error {
	hashType := alg.Hash()
	h := hashType.New()
	h.Write(signed)
	signed = h.Sum(nil)
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		switch alg {
		case PS256:
			return rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{})
		case RS256:
			return rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		default:
			return errors.New("rsa: unsupported alg")
		}
	case *ecdsa.PublicKey:
		switch alg {
		case ES256, ES384, ES512:
			if !ecdsa.VerifyASN1(pub, signed, signature) {
				return errors.New("ecdsa: Invalid signature")
			}
		default:
			return errors.New("ecdsa: unsupported alg")
		}
	case ed25519.PublicKey:
		switch alg {
		case EdDSA:
			if !ed25519.Verify(pub, signed, signature) {
				return errors.New("ed25519: invalid signature")
			}
		}
	default:
		return errors.New("unsupported public key")
	}
	return nil
}
