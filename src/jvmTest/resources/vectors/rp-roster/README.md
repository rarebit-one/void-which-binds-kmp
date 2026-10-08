# Relying-party org-trust golden vectors

Cross-implementation vectors for an RP's **org trust** (ADR-0016, amended G0
and G5): `rp.Roster`, `Verifier.CheckOrg`, `VerifyOrgWithPossession` and the
`Void-Which-Binds-Org` / `Void-Which-Binds-Roster` headers, over the org roster
of ADR-0014/0015. void-which-binds-go generates them
(`go test ./rp -run TestRPRosterVectors -update`) and replays every file.

## Layout

One file per case, `<case>.json`. Every key is a **test-only** deterministic
seed, listed so a consumer can re-sign and reproduce every token.

```jsonc
{
  "name":        "sovereign-member-authenticates",   // == file stem
  "description": "…",
  "org":         "ed25519:<hex>",       // the org id
  "founding":    "<token>",             // the founding op pinned beside it
  "pinned":      true,                  // false: the RP has not pinned the org
  "now":         1790859600,            // unix seconds every request runs at
  "keys":        { "P.D": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
                   "N":   { "id": "mp:<32 hex>" },
                   "M.W": { "id": "webauthn:es256:<130 hex>" } },
  "trust_pins":  [ "ed25519:<hex>" ],   // users pinned directly (rp.TrustStore)
  "stored": {                           // what the RP has recorded before the first request
    "roster":  [ "<token>" ],
    "persons": { "ed25519:<usr>": [ "<token>" ] }
  },
  "requests": [                         // replayed IN ORDER against one RP
    {
      "label":   "m",
      "mode":    "possession",
      "headers": { "Void-Which-Binds-Org": "…", "Void-Which-Binds-Roster": "…",
                   "Void-Which-Binds-Membership": "…" },
      "credential": "<token>",          // a device add, or a managed person's roster enrol
      "possession": "<token>",          // the possession proof, when the mode takes one
      "expect": {
        "authenticated": { "user": "…", "device": "…", "org": "…",
                           "role": "member", "person_kind": "sovereign" },
        // or "error": "<reason>"
        "alert":   [ "sha256:…" ],      // the conflict the OnConflict hook was called with
        "commits": { "roster": [ "<token>" ], "persons": { "<usr>": [ "<token>" ] } }
      }
    }
  ]
}
```

`commits` is exactly what the request wrote (roster ops, and person ops by
`usr`), sorted by hash; it is `{}` for a request that wrote nothing. A refused
request writes nothing, except a frozen org's conflict evidence.

## Modes

| mode             | what the RP does |
|------------------|------------------|
| `possession`     | `VerifyOrgWithPossession` (check, possession proof, commit) |
| `check_commit`   | `CheckOrg`, then `Commit` (possession proved some other way, e.g. a WebAuthn assertion) |
| `check_only`     | `CheckOrg` and no `Commit` |
| `check_deferred` | `CheckOrg` now; a later `commit` request commits it |
| `commit`         | `Commit` the `check_deferred` request named in `commit` |
| `truststore`     | no org header: `VerifyWithPossession` on the `TrustStore` path |
| `grant`          | `VerifyGrant` of `grant` for `grant_request` against the TrustStore |
| `pin`            | `Roster.Pin` of `founding` |
| `unpin`          | `Roster.Unpin` of the org |

Every `pin` and `unpin` starts a new pin generation (#133), even a `pin` of the
founding op already pinned: a `commit` of a request checked before it is
`pin_changed`, whatever founding op is pinned when it runs.

## Reasons

`unknown_org`, `org_frozen`, `not_on_roster`, `roster_removed`,
`unsupported_key`, `too_many_ops`, `bad_founding`, `pin_changed`, `removed`, `not_member`,
`expired`, `bad_signature`, `malformed`, `unknown_issuer`, and the possession
refusals `possession_signature`, `possession_malformed`, `possession_cert`,
`possession_expired`.
