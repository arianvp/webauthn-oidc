package jwk

import "errors"

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func (j *JWKSet) Get(kid string) (*JWK, error) {
	for _, p := range j.Keys {
		if p.KeyID == kid {
			return &p, nil
		}
	}
	return nil, errors.New("jwk: Pubkey not found")
}
