package authserver

import (
	"net/http"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"
)

type OpenidConfiguration struct {
	Issuer                            string                    `json:"issuer"`
	RegistrationEndpoint              string                    `json:"registration_endpoint"`
	AuthEndpoint                      string                    `json:"authorization_endpoint"`
	TokenEndpoint                     string                    `json:"token_endpoint"`
	JWKSURI                           string                    `json:"jwks_uri"`
	UserinfoEndpoint                  string                    `json:"userinfo_endpoint,omitempty"`
	SupportedAlgs                     []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
	SupportedScopes                   []string                  `json:"scopes_supported"`
	SubjectTypesSupported             []string                  `json:"subject_types_supported"`
	ResponseTypesSupported            []string                  `json:"response_types_supported"`
	GrantTypesSupported               []string                  `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string                  `json:"code_challenge_methods_supported"`
	ACRValuesSupported                []string                  `json:"acr_values_supported"`
	TokenEndpointAuthMethodsSupported []string                  `json:"token_endpoint_auth_methods_supported"`
}

func (r *OpenidConfiguration) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(r)
}
