# Security Event Token golden vectors

ADR-0023's deprovisioning suite: the RFC 8417 SETs moneta pushes (RFC 8935)
to each relying party, the RP's verification and its RFC 8935 answer, the
watermark rules it applies a SET by, the RP revocation watermark (#135), and
the transmitter's delivery-error classification. void-which-binds-go
generates every file from the real `secevent` code and fixed seeds
(`go test ./secevent -run TestSecEventVectors -update`); without `-update` the
test regenerates them, requires each file to be byte-identical, and replays
every verdict. The standard_id gem replays them.

Every file has `name` (== the file stem), `description` and `kind`. Keys,
seeds and the clock are as in `../oidc/README.md` (`now` = 1791000300, the
ADR's example `toe` = 1791000000).

| `kind` | what a port checks |
|--------|--------------------|
| `token` | under `jwks` and `pins`, verifying `token` gives `verdict`. With `verifier: set` the expectation is `expect_set` (`issuer`, `audience`, `now`, `max_age` seconds) and `rfc8935_err` is the RP's answer: `""` means 202, anything else is the `err` of a 400. With `verifier: idtoken` (`set-as-idtoken`) it is `expect_idtoken`, as in the oidc suite. `header`/`payload` are the decoded parts; signing them with `signer`'s seed reproduces `token`; for `ok`, minting the verified SET again gives `token` |
| `ordering` | each row's `rule` over its stamps gives `expect`: `revokes_session` is `login_iat ≤ toe`; `disables_link` is `toe ≥ last_login_iat`; `reenables_link` is `login_iat > toe` (toe of the disable). `set_iat` is informational: no rule reads it |
| `watermark` | run `steps` in order against one empty watermark store keyed by `(iss, sub)`: `advance` raises the subject's watermark to `toe` if greater; `check` creates a session from an ID token issued at `login_iat` and gets `verdict` (`ok`, or `session_revoked` when `login_iat ≤ watermark`) |
| `delivery` | each response (`status`, `body`) classifies as `outcome` (`delivered`, `retry`, `dead_letter`); `retryable` maps RFC 8935 codes to whether a 400 with that code is retried |

The SET verifier's rules (ADR-0023, "The RP's contract", steps 1–2): header
exactly `{"alg","kid","typ"}` with `typ` `secevent+jwt` and the same pinning
as the ID token; no JWT `sub`, `exp` or `nonce`; `aud` a single string equal to
this RP's client_id; `iss` equal to the configured issuer; `jti` 16 bytes of
base64url; `toe` present and ≤ `iat`; `sub_id` exactly
`{"format":"iss_sub","iss","sub"}` with `sub_id.iss == iss` and `sub` a person
id; exactly one event, of the two types, and a session-revoked payload whose
`event_timestamp` equals `toe`, with `initiating_entity` (`admin`, `user`,
`policy`) and `reason_admin.en`; `iat` no more than 7 days old and no more than
60 s in the future (both boundaries accepted). `txn` is optional to the
verifier.

Verdicts: `ok`, `malformed`, `wrong_type`, `alg`, `kid_not_pinned`,
`key_not_published`, `kid_thumbprint_mismatch`, `key_not_ed25519`,
`bad_signature`, `wrong_issuer`, `wrong_audience`, `forbidden_claim`, `sub_id`,
`events`, `unknown_event`, `toe_missing`, `toe_after_iat`, `iat_too_old`,
`iat_future`, `session_revoked`.

The RP answers a refusal of the key, algorithm or signature with
`invalid_key`, a wrong `iss` with `invalid_issuer`, a wrong `aud` with
`invalid_audience`, and anything else with `invalid_request`. It answers 202
for an accepted SET, a duplicate `jti`, an unknown `sub`, and an event
acknowledged without being applied.
