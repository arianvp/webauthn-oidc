package util

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"

	"github.com/duo-labs/webauthn/protocol"
)

func RegisterClient(redirectURIs []*url.URL) (string, error) {
	var origin string
	if len(redirectURIs) == 0 {
		return "", errors.New("No redirect_uris found")
	}
	for _, redirectURI := range redirectURIs {
		newOrigin := protocol.FullyQualifiedOrigin(redirectURI)
		if origin == "" {
			origin = newOrigin
		} else if origin != newOrigin {
			return "", errors.New("All redirect_uris must have the same origin")
		}
	}
	hash := sha256.Sum256([]byte(origin))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
