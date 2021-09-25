# Webauthn-oidc

Webauthn-oidc is a very minimal OIDC authorization server that only supports
webauthn for authentication.  This can be used to bootstrap a secure-by-design
passwordless identity provider for your company.


webauthn-oidc stores no state whatsoever.

After a user performs registration The audience of the OIDC token 


## Registration

To register a new webauthn credential, initiate an OAuth flow using the following parameters:

```
client_id=<your website>
```

e.g.

```
client_id=https://grafana.example.com
```

The user will be prompted to register a webauthn credential

## Login

To 
