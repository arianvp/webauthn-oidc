module github.com/arianvp/webauthn-oidc

go 1.18

replace github.com/duo-labs/webauthn => github.com/arianvp/webauthn v0.0.0-20210928001254-d9dcd044e9f9

require (
	github.com/duo-labs/webauthn v0.0.0-20210727191636-9f1b88ef44cc
	github.com/gorilla/sessions v1.2.1
	github.com/pkg/errors v0.9.1
)

require (
	github.com/cloudflare/cfssl v0.0.0-20190726000631-633726f6bcb7 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/fxamacker/cbor/v2 v2.2.0 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/gorilla/securecookie v1.1.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4 // indirect
)
