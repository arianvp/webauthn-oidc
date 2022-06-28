# Webauthn-oidc

!! This is probably full of game-breaking bugs   !!


[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/arianvp/webauthn-oidc)

Webauthn-oidc is a very minimal OIDC authorization server that only supports
webauthn for authentication.  This can be used to bootstrap a secure-by-design
passwordless identity system.

No accounts are stored in webauthn-oidc. Instead your account id is cryptographically derived from the attestation
certificate that your hardware token provides on signup. This means that we don't store any account information on the webauthn-oidc server. The ID token only contains information directly derivaeable from your attestation certificate.


No secrets are shared anywhere either. We implement PKCE for peforming the
challenge between client and server.


## Demo
In this demo you'll be able to authenticate to a local kubernetes kind cluster.

```
kind cluster create --config kind.yaml
```

Then follow the instructions printed by `kubelogin` to create an account backed by a hardware token with `cluster-admin` priveleges:
```
kubectl oidc-login setup --oidc-issuer-url https://oidc.arianvp.me --oidc-client-id ASF4Os1wJysH6uWvJV9PvyNiph4y4O84tGCHj1FZE
```

### Video demo

https://user-images.githubusercontent.com/628387/136426174-1e9b1400-2672-4949-8296-c27b28f102d6.mp4



## Registering an Oauth Client

webauthn-oidc implements the Dynamic Registration standard:

```
$ curl -s -XPOST https://oidc.arianvp.me/register --data '{"redirect_uris":["http://localhost:8000"]}' | jq .
{
  "client_id": "ASF4Os1wJysH6uWvJV9PvyNiph4y4O84tGCHj1FZEE8",
  "client_secret": "ASF4Os1wJysH6uWvJV9PvyNiph4y4O84tGCHj1FZEE8Mi_AdSNTdk2QoLyZGdGXhhhdbQqFAJZ-PEH6m1UYD_w"
}





```


## Login
Your identity is minted from the hash of your public key and credential id.
The original attestation of your Hardware token is stored in `localStorage` upon registration.
On authentication, you send both the attestation statement and the assertion statement
of the webauthn challenge legs. We then verify that the signature in the assertion is signed
with the key in the attestation statement and then mint an ID token with the following ID:
```
base64urlencode(sha256(credential_id||public_key||client_id)[20:])
```

## Future features:

* Enforce and check user verification and set `amr` values in the ID token accordingly
* Implement direct attestation, to allow us to get info on your token's hardware capailities (biometric , pin, secure element)
* Set `amr` values according to what kind of challenge was done (biometric vs pin)
* Allow people to set `acr_values` to require certain assurance level during login (e.g. biometric or FIPS ceritified)

## Deploy yourself

### Using NixOS


```nix
# /etc/configuration/flake.nix
{
  description = "Example deploy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-21.05";
    webauthn-oidc.url = "github.com:arianvp/webauthn-oidc";
  };

  outputs = { self, webauthn-oidc, nixpkgs }: {
    nixosModules.oidcWithNginx = {
      services.nginx.enable = true;
      services.webauthn-oidc = {
        host = "oidc.arianvp.me"; # CHANGE ME
        createNginxConfig = true;
      };
    };
    nixosConfigurations."webauthn-oidc" = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        webauthn-oidc.nixosModule
        self.nixosModules.oidcWithNginx
      ];
    };
  }
```



