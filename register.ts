"use strict";


import githubWebauthnJson from 'https://cdn.skypack.dev/@github/webauthn-json';

githubWebauthnJson.create();



async function registerPlatformAuthenticator() {
    if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) {
        let credential = await navigator.credentials.create({
            publicKey: {
                challenge: null,
                rp: { name: "null" },
                pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                user: {
                    id: null,
                    name: "Arian",
                    displayName: "Arian"
                },
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required"
                }
            }
        }) as PublicKeyCredential;
        return credential;
    }
    throw Error("no platform authenticator found");
}


async function get() {
  let credential = await navigator.credentials.get({publicKey: {
    challenge: null,

  }})
}

async function register(client_id : string) {
  let credential = await navigator.credentials.create({
    publicKey: {
      rp : {
        name: client_id // note that the id won't match client_id; as this is a federated login!
      },
      challenge: null, // TODO random
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      user: {
        id: null, // TODO random => userHandle
        name: null, // preferred_username
        displayName : null, // name
      }
    }
  });
}

// id_token_hint=<previous id token>
// login_hint=<credential id>
async function login(client_id : string, login_hint : string, id_token_hint : string) {

  await navigator.credentials.get({publicKey: {
   challenge: null, 
  }})
}