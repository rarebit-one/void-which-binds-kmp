# Org roster golden vectors

Cross-implementation vectors for the Void-Which-Binds **org roster** (ADR-0014,
amended #80, #99, #106 and the Phase 3 G0 errata) and its **re-root chain**
(ADR-0015, amended #80, #99, #106 and G3): the `void-which-binds.roster` op and
the deterministic `roster.Evaluate` over a set of roster ops plus the person-op
logs their signers need. void-which-binds-go generates them
(`go test ./roster -run TestVectors -update`), and void-which-binds-kmp replays
them verbatim.

## Layout

One file per case, `<case>.json`. Every key is a **test-only** deterministic
seed, listed so a consumer can re-sign and reproduce every `hash`.

```jsonc
{
  "name":        "sovereign-device-signs",    // == file stem
  "description": "…",
  "org":         "ed25519:<hex>",             // the org id (founding genesis)
  "founding":    "<b64url>.<b64url>",         // the pinned founding op token (also among ops)
  "now":         1790856000,                  // unix seconds Evaluate runs at
  "keys": {                                   // by label
    "org": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
    "P":   { "sign_seed": "<hex>", "id": "ed25519:<hex>" },   // a sovereign person's genesis
    "P.D": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },   // P's device D
    "M":   { "id": "mp:<32 hex>" },                           // a managed person (no key)
    "M.W": { "id": "webauthn:es256:<130 hex>" }               // a passkey (no seed here)
  },
  "persons": {                                // person-op tokens by usr: what persons(usr) returns
    "ed25519:<P>": [ { "label": "P/add-D", "token": "…", "hash": "sha256:…" } ]
  },
  "ops": [                                    // roster op TOKENS, in REVERSE build order
    { "label": "set-V", "token": "…", "hash": "sha256:…" }
  ],
  "expect": {
    "persons": {
      "ed25519:<V>": { "role": "viewer", "kind": "sovereign",
                       "assigned_by": ["sha256:…"], "expires": 1790861400 },  // expires omitted when none
      "mp:<M>":      { "role": "member", "kind": "managed",
                       "keys": { "webauthn:es256:…": false }, "assigned_by": ["sha256:…"] }
    },
    "removed":          [ "ed25519:<hex>" ],  // sorted
    "heads":            [ "sha256:<hex>" ],   // sorted
    "authority":        "ed25519:<org>",    // the current authority key (the org id, or a successor)
    "admin_high_water": 1,
    "frozen":           false,
    "conflict":         [ "sha256:<hex>" ],  // only while frozen: the conflicting re-roots, sorted
    "rejected":         { "sha256:<hex>": "missing_person_context" },
    "ineffective":      { "sha256:<hex>": "under_threshold" }
  },
  "enrolment": {                              // only in roster-token-to-enrolment-evaluate
    "usr": "ed25519:<hex>",
    "rejected": { "sha256:<hex>": "malformed" }
  }
}
```

- `ops` is **not** in causal order, and every permutation of `ops` (and of each
  person's ops) must give the same `expect`. The Go replay checks several
  permutations of every file.
- A person op withheld from `persons` is deliberate: it is how a case says "the
  evaluator was not given that past" (`bprev-missing-rejected`).
- `keys` in an `expect` person is a managed person's live enrolled keys: `true`
  for an Ed25519 key (can sign roster ops), `false` for a live passkey.
- `assigned_by` is the person's frontier ops (sorted), and `expires` the
  earliest `exp` among them.
- `rejected` reasons: `malformed`, `bad_signature`, `wrong_type`,
  `foreign_usr` (an `org` naming another org), `bad_prev`,
  `missing_person_context`, and, only in a set over the history cap,
  `unanchored` (ADR-0014, amended #122; see `../op-log-cap/README.md`). A re-root whose `succ` is the org id, its own
  `by`, the `by` or `succ` of an authority-shape re-root in its closure, or a
  `mem` in its closure, and an op whose `mem` is the `succ` of an
  authority-shape re-root in its closure, are `malformed`.
- `ineffective` reasons: `unauthorised`, `under_threshold`, `outranked`,
  `owner_required`, `last_owner`, and ADR-0015's `retired_authority` (an op of
  a retired authority key outside the retiring re-root's closure) and
  `reroot_conflict` (an eligible re-root that lost to a conflict, frozen or
  resolved, and any resolve by the authority key that settles nothing).
- An ineligible re-root signed by an authority key is `unauthorised` when its
  `by` is not the authority key in its closure, `under_threshold` when its
  admin signers independent of `by` miss rule 3 against `H(R)`, and
  `outranked` when they miss it once currency removes signers.
- A re-root's `succsig` signs `"void-which-binds-roster-reroot-v1\0" ‖ core`.
- A roster cosig signs `"void-which-binds-roster-cosig-v1\0" ‖ core ‖ "\0" ‖ usr
  ‖ "\0" ‖ join(bprev, ",")`, where the core is the op's payload with `cosig`
  and `succsig` omitted.
- A body that is not the canonical encoding of its fields (ADR-0014's field
  order, no unknown members, absent rather than empty optional lists, `prev`
  and `bprev` sorted and unique) is `malformed`.

## Cases

The case names are ADR-0014's "Golden vectors" list, one file each, plus
`unauthorised-reroot-cannot-raise-high-water` from its high-water section, and
ADR-0015's "Golden vectors" list (28 files, G3), plus four G3 cases that pin its
amended readings: `reroot-key-reuse-malformed`,
`retired-key-reset-changes-nothing`,
`authority-removal-in-closure-restores-currency` and
`reroot-citing-conflict-supersedes`.

Each case's `description` says what it pins; `roster/cases_test.go` holds the
hand-written expectations checked before a file is written.

Go consumers read the files through
`github.com/rarebit-one/void-which-binds-go/testvectors` (`RosterCases`,
`Roster`).
