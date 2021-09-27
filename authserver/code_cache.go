package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/duo-labs/webauthn/webauthn"
)

type state struct {
	codeChallenge       string
	codeChallengeMethod string
	redirectURI         string
	clientID            string
	nonce               string
	credential          *webauthn.Credential
}

type codeCache struct {
	m sync.Mutex
	c map[string]*state
}

func newCodeCache() *codeCache {
	return &codeCache{
		c: make(map[string]*state),
	}
}

func (cache *codeCache) newCode(state *state) (string, error) {
	cache.m.Lock()
	defer cache.m.Unlock()

	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	cache.c[code] = state
	return code, nil
}

func (cache *codeCache) del(code string) *state {
	cache.m.Lock()
	defer cache.m.Unlock()
	state := cache.c[code]
	cache.c[code] = nil
	return state
}
