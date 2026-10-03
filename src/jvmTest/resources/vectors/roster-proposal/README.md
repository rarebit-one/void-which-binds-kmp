# Roster proposal transport golden vectors

Cross-implementation vectors for the Void-Which-Binds **roster cosign
transport** (ADR-0014, "Proposal transport", specified by Phase 3 G4): the
`proposal` and `cosig` relay slot payloads, the verdict each side reaches on
them, and the roster op the proposer assembles. void-which-binds-go generates
them (`go test ./roster/proposal -run TestVectors -update`), and
void-which-binds-kmp replays them verbatim.

## Layout

One file per case, `<case>.json`. Every key is a **test-only** deterministic
seed, listed so a consumer can re-sign and reproduce every byte.

```jsonc
{
  "name":        "set-round-trip",            // == file stem
  "description": "…",
  "org":         "ed25519:<hex>",             // the org the receiver expects
  "founding":    "<b64url>.<b64url>",         // the founding op the receiver pinned
  "keys": {                                   // by label: "org", a person "P", P's device "P.D"
    "P.D": { "sign_seed": "<hex>", "id": "ed25519:<hex>" }
  },
  "proposal":    "{\"v\":1,\"slot\":\"proposal\",…}",  // the slot payload, exact bytes (ASCII)
  "pad":         0,                           // optional: append this many 0x20 bytes first
  "expect":      "ok",                        // Check's verdict: "ok" or a reason
  "cosigs": [                                 // only when expect is "ok"
    { "signer": "Q.D", "cosig": "{\"v\":1,\"slot\":\"cosig\",…}", "expect": "ok" }
  ],
  "assembled": {                              // only for a full round trip
    "signer":  "P.D",                         // signs the op as `by`
    "succ":    "K1",                          // a re-root only: signs succsig
    "op":      "<b64url>.<b64url>",           // the minted roster op, exact
    "hash":    "sha256:<hex>",
    "roster":  [ "sha256:<hex>" ],            // its closure's ops, founding included, hash order
    "persons": { "ed25519:<P>": [ "sha256:<hex>" ] },  // every needed person op, by person
    "verdict": "effective"                    // or roster.Evaluate's ineffective reason
  }
}
```

## Replay

1. Check every key: `ed25519(sign_seed)` renders as `id`.
2. `Check(proposal ‖ pad×" ", {org, founding})` with **no** local replica:
   the proposal alone must suffice. Compare its reason (or `ok`).
3. For each cosig, `VerifyCosig` against that checked proposal and compare.
   For an `ok` cosig, re-mint it as the cosigner (`Cosign` with the signer's
   seed, the entry's `usr` and `bprev`, and its own `persons` as the log) and
   compare the payload byte for byte.
4. If `assembled` is present, `Assemble` with the `ok` cosigs (entries in key
   order), `succ` signing succsig for a re-root, and compare `op`, `hash`,
   `roster`, `persons` and `verdict`.

## The format (normative summary; ADR-0014 is the source)

```
proposal {"v":1,"slot":"proposal","core":b64url(core),"usr"?,"bprev"?:[opHash…],
          "roster":[token…],"persons":{usr:[token…]}}
cosig    {"v":1,"slot":"cosig","entry":{"by","usr","bprev"?,"sig"},"persons":{usr:[token…]}}
```

- Canonical JSON: exactly Go's `encoding/json` encoding of the parsed value in
  this member order, no whitespace, no unknown or case-variant members.
  `roster` and `persons` are always present (`[]`, `{}`); `usr`/`bprev` are
  absent when empty. Token lists are in op-hash order, without duplicates;
  person lists are non-empty; `persons` keys are canonical `ed25519:` keys.
- `core` is unpadded base64url of `roster.Draft.Core`, and must be the
  canonical core of the draft it parses to. `usr`/`bprev` must equal the
  core's.
- Caps, checked before any token is parsed: proposal 524288 bytes, cosig
  131072 bytes, `roster` ≤ 256, `persons` ≤ 64 persons and ≤ 256 ops in all;
  a cosig carries at most one person and ≤ 128 ops.
- Refusal order and reasons (ADR-0014 "Proposal transport" spells out each
  step): decoding either slot gives `too_large` (bytes), `malformed` (not a
  JSON object), `bad_version`, `malformed` (slot), `too_large` (counts),
  `malformed` (canonical form); then a proposal `bad_core`,
  `restatement_mismatch`, `wrong_org`, `bad_context`,
  `missing_roster_context`, `unexpected_context`, `missing_person_context`,
  `bad_core` (a structural rule of the op in its closure),
  `proposer_not_authorised`; and a cosig `malformed` (entry shape),
  `bad_cosig`, its person context (`unexpected_context`, `bad_context`,
  `missing_person_context`), `cosigner_not_counted`. Each vector refuses at
  exactly one step, so its reason does not depend on the order within a step.

## Cases

`set-round-trip` and `reroot-round-trip` are full ceremonies. The refusals:
`proposal-missing-roster-context` (#114 item 1), `proposal-missing-person-context`,
`cosig-missing-person-context` (#114 item 2), `restatement-mismatch`,
`wrong-org`, `oversize-bytes`, `too-many-roster-ops`, `cosig-too-many-persons`,
`bad-version`, `tampered-core`, `cosig-over-different-core`,
`unexpected-roster-context`, `proposer-not-authorised`,
`cosigner-not-counted`, `set-exp-reduction-refused` and
`reroot-succ-reuse-refused` (both `bad_core`: closure-dependent structural
rules), and `person-signed-reset-refused` (authority-only kinds). Each case's `description` says what it pins.

Go consumers read the files through
`github.com/rarebit-one/void-which-binds-go/testvectors`
(`RosterProposalCases`, `RosterProposal`).
