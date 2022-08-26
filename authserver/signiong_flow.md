client_id should both allow us to check redirect_uri _and_ the creator of the app TODO


Alice wants to join Bob's team

1. Alice goes to /join?group=blah
2. Will do a login ceremony (with challenge) to see if Alice owns the presented `attestation_response` by checking `assertion_response`
3. Server returns a signed object `readytosign` saying `attestation_response` is ready to attest
4. Alice creates a link containing `readytosign` and sends it to Bob
5. Bob opens the link. Gets a visual of the attestation response (TODO Add ability to visually compare to Alice? Emoji)
6. Bob performs an assertion ceremony taking the `challenge` + the `readytosign` as input.  and gets a signed object back
7. 