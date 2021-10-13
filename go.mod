module github.com/arianvp/webauthn-oidc

go 1.16

replace github.com/duo-labs/webauthn => github.com/arianvp/webauthn v0.0.0-20210928001254-d9dcd044e9f9

require (
	github.com/duo-labs/webauthn v0.0.0-20210727191636-9f1b88ef44cc
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/gorilla/sessions v1.2.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0
)
