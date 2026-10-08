# OIDC golden vectors

ADR-0023's OpenID Provider suite: the ID token moneta mints for a `login`
approval, the JWKS and pinning an RP verifies it under, PKCE S256, and the
discovery document. void-which-binds-go generates every file from the real
`oidc` code and fixed seeds (`go test ./oidc -run TestOIDCVectors -update`);
without `-update` the test regenerates them, requires each file to be
byte-identical, and replays every verdict. The standard_id gem and
void-which-binds-kmp replay the same files.

Every file has `name` (== the file stem), `description` and `kind`.

Keys are test-only: each seed is `SHA-256("void-which-binds/testvectors/adr-0023/" + label)`,
listed under `keys` as `{seed (hex), jwk}`. `current` and `next` are moneta's
`assert` and `assert-next`; `attacker` is a key that is published but never
pinned; `x25519` signs the token whose pinned JWK claims curve X25519. The
replaying clock is `expect.now` = 1791000300.

| `kind` | what a port checks |
|--------|--------------------|
| `jwk` | `rfc8037_thumbprint` is RFC 8037 Appendix A.3's (`kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`) for `rfc8037_jwk`; each key's JWK (`{"kty","crv","x","kid","use","alg"}`, in that order) and `kid` = RFC 7638 thumbprint over `{"crv","kty","x"}`; `jwks_current` and `jwks_rotation` are the exact JWKS bytes |
| `idtoken` | under `jwks` and `pins`, verifying `token` with `expect` (`issuer`, `client_id`, `org`, `nonce`, `now`, `leeway` seconds) gives `verdict`. `header` and `payload` are the token's decoded parts, and (unless `tampered`) Ed25519-signing `base64url(header) "." base64url(payload)` with `signer`'s seed reproduces `token` byte for byte. For `ok`, minting the verified claims again gives `token` |
| `pin-rotation` | `jwks` lists `current` and `next`; each row verifies `tokens[row.token]` with `pins` = `row.pins` and gets `row.verdict` |
| `pkce` | `check: challenge` is the authorize endpoint (`method`, `challenge`); `check: verifier` is the token endpoint (`challenge`, `verifier`); each gets `verdict` |
| `discovery` | the document for `issuer`, `authorization_endpoint` and `token_endpoint` is `document`, byte for byte |

Verifier rules the verdicts encode (ADR-0023, "The ID token"): the header is
exactly `{"alg","kid","typ"}`; `typ` is `JWT`; `alg` is `EdDSA` (Go also
accepts RFC 9864's `Ed25519`); `kid` is pinned, and the key set holds a key
whose recomputed thumbprint equals it, whose stated `kid` equals it, and
which is `OKP`/`Ed25519`; the signature verifies; there is no `events`
claim; `aud` is a single string; `iss`, `aud`, `org` and `nonce` equal
`expect`; `exp > now − leeway` and `iat < now + leeway`. NumericDates are
non-negative JSON integers. JSON is strict: a duplicate member name anywhere
is malformed.

Verdicts: `ok`, `malformed`, `wrong_type`, `alg`, `kid_not_pinned`,
`key_not_published`, `kid_thumbprint_mismatch`, `key_not_ed25519`,
`bad_signature`, `wrong_issuer`, `wrong_audience`, `wrong_org`, `nonce`,
`expired`, `iat_future`, `forbidden_claim`, `pkce`.

The `discovery` vector's endpoint paths are fixtures; the protocol fixes only
`jwks_uri` = issuer + `/.well-known/jwks.json`.
