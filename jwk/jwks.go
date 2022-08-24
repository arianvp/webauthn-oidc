package jwk

import "fmt"

type JWKSet struct {
	Keys   []JWK `json:"keys"`
	keyMap map[string]*JWK
}

func (j *JWKSet) Get(kid string) (*JWK, error) {
	if j.keyMap == nil {
		j.keyMap = make(map[string]*JWK)
		for _, key := range j.Keys {
			j.keyMap[key.KeyID] = &key
		}
	}
	key, ok := j.keyMap[kid]
	if !ok {
		return nil, fmt.Errorf("no key found for kid: %s", kid)
	}
	return key, nil
}
