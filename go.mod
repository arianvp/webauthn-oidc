module github.com/arianvp/webauthn-oidc

go 1.16

replace github.com/duo-labs/webauthn => github.com/arianvp/webauthn v0.0.0-20210928001254-d9dcd044e9f9

require (
	github.com/duo-labs/webauthn v0.0.0-20210727191636-9f1b88ef44cc
	github.com/gorilla/sessions v1.2.1
	github.com/hashicorp/cap v0.1.1
	github.com/pkg/errors v0.9.1
	gopkg.in/square/go-jose.v2 v2.6.0
)
