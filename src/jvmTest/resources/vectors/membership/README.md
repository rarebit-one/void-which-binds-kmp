# Membership op-set golden vectors

Cross-implementation vectors for the Void-Which-Binds **membership op-set** (ADR-0007):
the v3 `enrolment` op (`add` / `remove`) and the deterministic `Evaluate` over a
set of ops. void-which-binds-go generates them (`go test ./enrolment -run TestVectors
-update`), and every other implementation — void-which-binds-kmp's `Membership.evaluate`,
heyarr-core's `deviceauth`, All Thing's `internal/membership` — replays them
byte-for-byte. A vector that passes here and fails there is a divergence in the
port, never a "flaky key".

## Layout

One file per case, `<case>.json`, all keys **test-only** (deterministic seeds
appear in the file so a consumer can re-sign and reproduce every `hash`):

```jsonc
{
  "name":        "genesis-a-b",                 // == file stem
  "description": "genesis admits A; A admits B; …",
  "usr":         "ed25519:<hex>",               // the identity = genesis public key
  "now":         1788267600,                    // unix seconds Evaluate is run at
  "keys": {                                     // test seeds (hex), by label
    "genesis": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
    "A":       { "sign_seed": "<hex>", "enc_seed": "<hex>", "id": "ed25519:<hex>" }
  },
  "ops": [                                      // op TOKENS, in REVERSE build order
    { "label": "add-A", "token": "<b64url>.<b64url>", "hash": "sha256:<hex>" }
  ],
  "expect": {
    "members":     { "ed25519:<A>": { "admitted_by": "sha256:<hex>", "denc": "x25519:<hex>", "admitted_at": 1788264000, "expires": 1796040000 } },
    "removed":     [ "ed25519:<B>" ],           // sorted
    "heads":       [ "sha256:<hex>" ],          // sorted
    "rejected":    { "sha256:<hex>": "bad_prev" },      // structurally invalid: uncitable
    "ineffective": { "sha256:<hex>": "unauthorised" }   // valid but changes nothing right now
  }
}
```

- `ops` is deliberately **not** in causal order: a consumer must resolve `prev`
  itself. Feeding the same list in any permutation must give the same `expect`
  (the CRDT property the Go property tests assert).
- `hash` is `"sha256:" + hex(sha256(token))` and is authoritative for `prev`.
- Every op and cert is **typed** (ADR-0009): `typ` is `void-which-binds.op` or
  `void-which-binds.cert`, second in the body after `v`. Gen2 is typed-only
  (ADR-0022), so an untyped or gen1-typed (`voidbind.*`) token is `malformed`.
- A cosig signs `void-which-binds-cosig-v1\0 ‖ core`, where the core is the
  op's signed payload with `cosig` omitted and **`typ` kept**. A port that
  rebuilds the core without `typ` gets `under_threshold` in
  `cosig-threshold-met`.
- `denc` for label X is `"x25519:" + enc_seed` — a stand-in string; `Evaluate`
  treats it as opaque.
- Every key-bearing field (`usr`, `by`, `dev`, each cosig `by`) must be the
  key's canonical rendering, byte for byte (#116): `ed25519:<64 lowercase hex>`,
  or for `dev` also `webauthn:es256:<130 lowercase hex>` naming a valid P-256
  point. No surrounding whitespace, no upper case, no other key kind. Anything
  else is `malformed`. A port that trims or case-folds before comparing keys
  diverges on `noncanonical-key-rendering-malformed`.
- `rejected` reasons: `malformed`, `bad_signature`, `foreign_usr`, `bad_prev`.
  A rejected op is keyed by the hash of its raw token bytes.
- `ineffective` reasons: `unauthorised`, `outranked`, `removed`, `superseded`,
  `expired`, `not_yet_valid`, `under_threshold` (ADR-0008). An ineffective op is still part of the state (citable as
  `prev`, counts toward `heads`).

## Cases

| case | what it pins |
|------|--------------|
| `genesis-a-b` | genesis → A → B, all members; heads = [add-B] |
| `a-removes-b` | A removes B: B in `removed`, re-add by A is `removed` |
| `concurrent-mutual-remove` | A and B remove each other concurrently: **seniority wins** — B's remove is `outranked`, A stays, B removed |
| `junior-remove-acknowledged` | B removes A and A's later remove *cites* it: not a fork — A's remove is `unauthorised` |
| `readd-refused-unless-genesis` | a removed dev re-added by a member, or by genesis without citing the remove, stays removed; by genesis citing the remove is a member |
| `expired-add` | an add past its `exp` is not a member; an op it signed after expiry is `unauthorised`; one signed while valid stands |
| `self-renew-extends-membership` | a device renews itself (a self re-add under its own key) while its add is valid and stays a member past the first add's expiry; a self re-add after the add lapsed is `unauthorised` |
| `bad-prev` | an op citing an unknown hash is `bad_prev`, and so is anything built on it; a member op with `prev: []` is `malformed` |
| `foreign-usr` | an op whose `usr` is another identity is `foreign_usr` |
| `junk` | unparseable / tampered tokens are rejected, never fatal |
| `v2-cert-as-genesis-add` | v1 and v2 certs reinterpreted as `{op:add, by:usr, prev:[]}` |
| `concurrent-add-and-remove` | remove concurrent with add wins; a member's earlier admissions survive its removal (no cascade through history) |
| `stale-heads-after-removal` | a removed device keeps signing with stale heads: every op is void (`outranked`), and ops by the devices it "admitted" are `unauthorised` |
| `senior-concurrent-add-survives` | a senior's add concurrent with a junior's remove of it stands; a junior's add concurrent with a senior's remove of it is void |
| `cosig-reserved` | a remove carrying `cosig` entries in a fleet that never exceeded two devices (k=1): the cosig is moot and the remove is honoured as if without it |
| `cosig-threshold-met` | ADR-0008: high-water 3 (k=2); a remove co-signed by a second member of its closure is effective |
| `cosig-threshold-unmet` | high-water 3 (k=2); a remove with only the primary signature is `under_threshold` and removes nothing |
| `cosig-nonmember-ignored` | a cosig by a key outside the remove's closure verifies but does not count: `under_threshold` |
| `cosig-below-three` | high-water 2 (k=1): a single-signature remove is effective |
| `cosig-genesis-bypass` | a genesis remove bypasses the threshold entirely, even with three members and no cosig |
| `cosig-minimal-prev-downgrade-refused` | anchoring a remove to an old 2-member `prev` does not lower k: the high-water ignores `prev` |
| `cosig-backdated-iat-downgrade-refused` | backdating a remove's `iat` does not lower k: the high-water ignores `iat` |
| `gen1-tokens-rejected` | ADR-0022: genesis-signed gen1 tokens (an untyped op, an op typed `voidbind.op`, a cert typed `voidbind.cert`) are `malformed` and uncitable; an op built on one is `bad_prev` |
| `gen1-cosig-domain-ignored` | ADR-0022: `cosig-threshold-met` with the cosig made under the gen1 domain `voidbind-cosig-v1`. It does not verify, so the remove is `under_threshold` |
| `webauthn-member-not-in-high-water` | ADR-0018: one Ed25519 phone plus two `webauthn:` passkeys gives N=1, k=1, so a single-signature remove is effective |
| `webauthn-with-three-phones` | ADR-0018: three Ed25519 phones plus a passkey gives N=3, k=2, unchanged by the passkey |
| `webauthn-removed-still-not-counted` | ADR-0018: a passkey added and later removed never raises N, so N stays 2 and a single-signature remove is effective |
| `noncanonical-key-rendering-malformed` | #116: an op whose `dev` (Ed25519 or `webauthn:`), `by` or `usr` is a whitespace-padded or uppercase-hex rendering of a key is `malformed`, and an op citing one is `bad_prev`; the padded add never raises N, so N=2, k=1 and A's single-signature remove of B is effective |
| `cosig-two-renderings-refused` | #116: the k=2 bypass. With N=3, a remove co-signed by a padded or uppercase rendering of its own signer's key is `malformed`; a canonical self-cosig is a duplicate signer, `under_threshold` |

Since gen2 is typed-only, the former `typed-genesis-a-b`, `typed-mixed-history`
and `typed-cosig-threshold-met` cases were folded into `genesis-a-b`,
`v2-cert-as-genesis-add` and `cosig-threshold-met`, which are now typed
throughout.

Regenerate with `go test ./enrolment -run TestVectors -update`. Go consumers
read these files through `github.com/rarebit-one/void-which-binds-go/testvectors`
(`MembershipCases`, `Membership`) rather than copying them; void-which-binds-kmp keeps a
verbatim copy that its CI diffs against this directory at a pinned commit.
