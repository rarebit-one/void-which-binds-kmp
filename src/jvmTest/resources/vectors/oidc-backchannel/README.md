# OIDC back-channel golden vectors

ADR-0024's back-channel action approval: the approval assertion moneta mints
when a person approves a `step-up` or `consent` action through
`/oidc/bc-authorize` and the CIBA poll, the RP's verification of it, the
binding_message vetting and summary composition, the consent params and scope
mapping, the action digests an RP recomputes, the polling arithmetic, and the
discovery additions.
void-which-binds-go generates every file from the real `oidc` code and the
ADR-0023 seeds (`go test ./oidc -run TestOIDCBackchannelVectors -update`);
without `-update` the test regenerates them, requires each file to be
byte-identical, and replays every verdict. The standard_id gem
(`standard_id-void_which_binds`) and void-which-binds-kmp replay the same files.

Every file has `name` (== the file stem), `description` and `kind`. Keys,
seeds and the clock are as in `../oidc/README.md` (`now` = 1791000300). The
moneta client is `nutripod-web` with registry display name `Nutripod`. The
fixed `jti`s are the first 16 bytes of
`SHA-256("void-which-binds/testvectors/adr-0024/jti/" + label)`.

| `kind` | what a port checks |
|--------|--------------------|
| `assertion` | under `jwks` and `pins`, verifying `token` gives `verdict`. With `verifier: assertion` the expectation is `expect` (`issuer`, `client_id`, `org`, `subject`, `kind`, `action_digest`, `now`, `leeway` seconds); with `verifier: idtoken` it is `expect_idtoken` (as in the oidc suite); with `verifier: set` it is `expect_set` (as in the secevent suite). `header`/`payload` are the decoded parts and (unless `tampered`) signing them with `signer`'s seed reproduces `token`. For `ok`, minting the verified claims again gives `token` byte for byte |
| `summary` | each row runs the action builder on (`client_id`, `display_name`, `kind`, `binding_message`, `params`) and gets `verdict`; for `ok`, the action's summary is `summary` |
| `consent-params` | each row's `params`, checked as consent params under the moneta client `client_id`, gets `verdict` |
| `consent-scope-mapping` | each row's OAuth `scope`, mapped under the moneta client `client_id`, gets `verdict`, and for `ok` the policy scope `policy_scope` |
| `action-digest` | each row's action, built from (`client_id`, `display_name`, `kind`, `binding_message`, `params`), has `resource` and `summary`; the ADR-0019 digest of (`kind`, `resource`, `summary`, `params`) is `action_digest`, unpadded base64url |
| `poll` | replaying `polls` in order against one request issued at time 0 (`interval` 5 s, `slow_down` +5 s, at most 60 polls), each poll at `at` seconds gives `verdict` (`slow_down`, or `ok`: the approval's state answers) and leaves `interval` seconds and `polls` polls |
| `discovery` | the document for `issuer`, `authorization_endpoint`, `token_endpoint` and `backchannel_authentication_endpoint` is `document`, byte for byte |

The assertion's header is exactly `{"alg":"EdDSA","kid":"<thumbprint>","typ":"vwb-approval+jwt"}`
and its payload, in byte order, is exactly
`{"iss","sub","aud","org","iat","exp","auth_time","amr","act_digest","kind","jti"}`.
Verifier rules the verdicts encode (ADR-0024, "The RP's contract", step 4):
the JWS layer and pinning are the ID token's, with `typ`
`vwb-approval+jwt` (so an ID token or a SET is `wrong_type` here, and an
assertion is `wrong_type` to the ID-token and SET verifiers); any claim
outside the eleven is `forbidden_claim`; `aud` is a single string; every claim
is present and well-typed, `kind` is `step-up` or `consent`, `act_digest` is
unpadded base64url of 32 bytes, `jti` of 16, and `amr` is exactly
`["mfa","pop","user"]` or `["mca","pop"]` (otherwise `malformed`); `iss`,
`aud`, `org`, `sub`, `kind` and `act_digest` equal the expectation;
`exp − iat ≤ 300` and `auth_time ≤ iat` (otherwise `malformed`);
`exp > now − leeway` and `iat < now + leeway`.

Builder rules: a binding_message is 1–200 bytes of UTF-8 in NFC, with no
Cc, Cf, Zl or Zp character and no leading or trailing White_Space
(`invalid_binding_message`). The summary is `<display_name>: <binding_message>`,
and for consent ` (scopes: <s1>, <s2>, …)` from params. Params are one flat
JSON object, member names `[a-z][a-z0-9_]{0,31}`, string values only (consent:
`scopes` is the one array of strings), byte-identical to its RFC 8785 (JCS)
serialisation. Consent params are exactly `client_id`, `scopes`, and optional
`redirect_uri` and `resource` (printable ASCII, 1–2048 bytes); `scopes` holds
1–32 entries, sorted and de-duplicated. An OAuth scope matching
`[a-z0-9._-]+(:[a-z0-9._-]+)*` maps to
`oidc:client/<client_id>/<scope with ':' replaced by '/'>`, which must be a
valid ADR-0017 scope of at most 128 bytes. Anything else is `invalid_request`.

Verdicts: `ok`, `malformed`, `wrong_type`, `alg`, `kid_not_pinned`,
`wrong_issuer`, `wrong_audience`, `wrong_org`, `wrong_subject`, `wrong_kind`,
`act_digest_mismatch`, `expired`, `iat_future`, `forbidden_claim`,
`invalid_binding_message`, `invalid_request`.

The NFC check accepts any string already in NFC, non-ASCII included: the
`nfc-non-ascii` row is an accepted message with a precomposed U+00E9, and the
`not-nfc` row refuses the same text spelled with a combining U+0301. A string
that is not NFC is refused, never normalised. The check also enforces the
Stream-Safe Text Format, so more than 30 consecutive non-starters are refused
even when otherwise NFC; an implementation must refuse those too.
The endpoint paths in `discovery-backchannel` are fixtures.
