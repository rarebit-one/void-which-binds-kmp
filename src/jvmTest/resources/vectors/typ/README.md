# Token-type (`typ`) golden vectors: ADR-0009

These are cross-implementation vectors for the `typ` claim that
[ADR-0009](../../../docs/adr/0009-token-type-claim.md) adds to every signed
token. void-which-binds-go generates them with `go test ./testvectors -run
TestTypVectors -update` and replays them through the real verifiers. Other
implementations copy the files verbatim and replay them too.

Gen2 is **typed-only** ([ADR-0022](../../../docs/adr/0022-gen2-hard-cutover.md)):
every minter emits `typ`, and every verifier refuses a token without one, or
with a gen1 `voidbind.*` value, as `wrong_type`. There are no ADR-0009 phases
left, so each check has one expected verdict.

## Layout

There is one file per case, `<case>.json`. Every key in them is **test-only**,
with a deterministic seed:

```jsonc
{
  "name": "typed-cert",                       // == file stem
  "description": "…",
  "now": 1790251200,                          // unix seconds every check runs at
  "keys": { "user": { "sign_seed": "<hex>", "id": "ed25519:<hex>" }, "device": { … } },
  "tokens": { "token": "<b64url>.<b64url>", … },
  "grant_request": { "principal": "device:alpha", "resource": "space:one", "capability": "read" },
  "checks": [
    { "verifier": "possession", "token": "token", "key": "device", "cert": "cert", "expect": "ok" }
  ]
}
```

- **`verifier`** is one of the following:
  - `grant`: `grant.Verify` with `key` as the only enrolled issuer and `grant_request`.
  - `cert`: `VerifyCert` against the pinned `key`.
  - `cert_user`: the `CertUser` hint.
  - `possession`: `VerifyPossession` with device `key` and the cert token labelled `cert`.
  - `op`: `VerifyOp`.
  - `op_user`: the `OpUser` hint.
  - `cosig`: `VerifyCosig` of the co-signature by `key` carried in the op
    token: an Ed25519 signature over `void-which-binds-cosig-v1` ‖ `0x00` ‖
    the op's core (its signed body with `cosig` omitted and `typ` kept).
- **`expect`** is the verdict the verifier must reach: `ok`, `wrong_type`,
  `malformed`, `bad_signature`, `expired`, `not_yet_valid` or `cert_mismatch`.
  Grant and cert verdicts use their packages' reason enums.
- **Check order.** The `typ` check runs right after the token envelope splits,
  before the signature and before any other field. A mistyped or untyped token
  is therefore `wrong_type` whatever key it is checked under. A `typ` that is
  not a JSON string (`null` included), or a case-variant key such as `"Typ"`,
  is `malformed`. A body that is not a JSON object at all is not a type
  question. It goes through the verifier's usual checks in their usual order,
  so a body corrupted in flight still fails the signature check.
- **Byte layout.** In every typed body, `typ` is the **second** member,
  immediately after `v`. Values are dotted, such as `void-which-binds.cert`,
  so no encoder ever escapes them. `void-which-binds.roster` and
  `void-which-binds.delegation` are reserved.

## Cases

| case | what it pins |
|------|--------------|
| `typed-grant`, `typed-cert`, `typed-possession`, `typed-op` | each kind, typed, verifies under its own verifier, and every other verifier returns `wrong_type`. A typed cert also verifies at `op` as a genesis add |
| `overlap-grant-v1-cert-v1` | grant v1 and cert v1 share `v:1`. An untyped body with both shapes' fields was accepted by **both** verifiers before gen2; it is now `wrong_type` at both. Typed, it is accepted only as the kind its `typ` names |
| `overlap-cert-v2-possession-v2` | cert v2 and possession share `v:2`. The same attack, with one key acting as both user and device |
| `typ-malformed` | wrong case or unknown value gives `wrong_type`. Non-string or `null`, a case-variant key, or a kind at a version it lacks gives `malformed` |
| `legacy-untyped` | the untyped tokens gen1 minted before ADR-0009 phase 2: every verifier, `op`/`op_user` included, refuses them as `wrong_type` |
| `gen1-typ` | well-formed, validly signed tokens typed with the gen1 values (`voidbind.grant`, `voidbind.cert`, `voidbind.possession`, `voidbind.op`): `wrong_type` everywhere. There is no `wrong_generation` verdict; a gen1 `typ` is simply foreign |
| `gen1-domain` | a v3 remove carrying a device cosig: under the gen2 cosig domain the cosig is `ok`; under the gen1 domain `voidbind-cosig-v1` it is `bad_signature` (the op itself verifies either way) |

The typed membership ops, including a cosigned remove whose cosig covers the
typed core and a cosig made under the gen1 domain, are in `../membership/`.
