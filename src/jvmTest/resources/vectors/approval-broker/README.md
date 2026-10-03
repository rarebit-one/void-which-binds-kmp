# Action-approval broker golden vectors

Cross-implementation vectors for the Void-Which-Binds **action-approval
broker** (ADR-0019, amended 2026-10-03, G9b): the cases the byte layer
(`../approval/`) defers because they need broker state. Each file is one broker
serving one org: its pinned org and recorded roster and person logs (ADR-0016),
its role policy, its stored challenges with their actions and the handles
minted for them, and its issued fetch nonces. A sequence of steps (approvals,
consumptions, fetches and fetch-nonce requests) is replayed **in order** against
it, and each step's verdict, wire answer and writes must come out as listed.
void-which-binds-go generates them
(`go test ./approval -run TestApprovalBrokerVectors -update`) and replays every
file.

## Layout

```jsonc
{
  "name": "fetch-wrong-approver",            // == file stem
  "description": "…",
  "org": "ed25519:<hex>",                    // the one org this broker serves
  "founding": "<token>",                     // pinned beside it
  "audience": "https://broker.example",      // the broker's origin
  "webauthn_rps": [ { "rp_id": "broker.example", "origins": [ "https://broker.example" ] } ],
  "policy": { "owner": [ … ], "member": [ "app:read", "do:team/ops" ], "viewer": [ "app:read" ] },
  "rate_limits": { "fetch_nonce": 60, "fetch": 10, "window": 60 },   // per source, per window (s)
  "keys": {                                  // test-only seeds; "N" is a managed person id
    "M.D": { "sign_seed": "<hex>", "id": "ed25519:<hex>" },
    "N.W": { "p256_scalar": "<hex>", "id": "webauthn:es256:<hex>" },
    "N":   { "id": "mp:<32 hex>" }
  },
  "stored": { "roster": [ "<roster op>" ], "persons": { "<usr>": [ "<person op>" ] } },
  "challenges": [                            // stored pending, with the TRUE match number
    { "label": "c", "id": "<32 hex>", "nonce": "<hex>", "audience": "…",
      "issued_at": 1791028800, "expires_at": 1791028920, "match_number": 42,
      "candidates": [17, 42, 86], "action_digest": "<hex>", "resource": "do:team/ops", "ttl": 600,
      "action": { "kind": "deploy", "resource": "do:team/ops", "summary": "…", "params": "<hex>" },
      "handles": [ { "handle": "<43 b64url>", "person": "<person id>" } ] }
  ],
  "nonces": [ { "nonce": "<43 b64url>", "issued_at": 1791028810 } ],  // issued, unspent
  "mints": [ … ],                            // every signature, as in ../approval/
  "steps": [
    { "label": "fetch", "op": "fetch", "now": 1791028820, "source": "192.0.2.10",
      "request": { "handle": "…", "nonce": "…", "credential": "<token>", "proof": "<b64url>" },
      "expect": { "error": "fetch_wrong_approver", "status": 404,
                  "body": "{\"error\":\"not_found\"}",
                  "writes": { "nonces_spent": [ "<nonce>" ] } } }
  ]
}
```

### Steps

| `op` | what runs | fields |
|------|-----------|--------|
| `approve` | `Broker.Approve(challenge, assertion)` at `now` | `challenge` (an id), `assertion` (the approval body) |
| `consume` | `Broker.Consume(id, digest, now)` | `approval` (the label of the `approve` step whose record), or `approval_id` (a literal id); `digest` (hex) |
| `fetch` | `POST /approval/fetch` from `source` | `request` (the body), or `body` (raw bytes, for an undecodable body) |
| `fetch_nonce` | `POST /approval/fetch-nonce` from `source` | — |

`repeat: n` runs a step n times; every run has the same verdict and `writes`
is their sum.

### Expectations

- `error`: for `approve` and `consume`, the refusal word; for `fetch`, the
  reason the broker **logs** (it is never on the wire); for `fetch_nonce`,
  `fetch_nonce_rate_limited` with a `429`. Absent means accepted.
- `status` and `body`: the HTTP answer of a `fetch` (exact bytes) or a
  `fetch_nonce` (status only; the nonce is random). Every fetch refusal is
  `404` with exactly `{"error":"not_found"}`, whatever the reason.
- `approval`: the record an `approve` stored, or a `consume` returned
  (`challenge`, `action_digest`, `resource`, `person`, `approver`,
  `approved_at`, `not_after`, `single_use`, `consumed`). Its id is random and
  not listed.
- `writes`: exactly what the step wrote. `persons` and `roster` are the
  approver's fresh ops (an accepted approval only); `approved` the challenge
  ids moved to approved; `consumed` the records consumed (by their `approve`
  step's label); `nonces_spent` the issued nonces removed; `nonces_issued`
  how many were issued. `{}` is nothing: **a refused approval writes nothing,
  and a fetch writes nothing but the nonce it spent.**

## Order

An approval runs: the challenge is held (`unknown_challenge`) and pending
(`already_approved`); the window (`challenge_expired`), the assertion's
credential, signature and number (`malformed`, `number_mismatch`), the stored
action's digest and resource; the approver authenticated by `CheckOrg` under
the broker's own org, persisting nothing (`approver_not_member`,
`approver_removed`, `approver_not_on_roster`); the signature under its member
key (`bad_assertion`, or ADR-0018's passkey word); `resource ∈ policy(org,
role)` (`approver_not_authorised`); then the commit.

A fetch runs: the source's limit is counted; the nonce is spent whatever
follows (`fetch_nonce_spent`: not 32 bytes of canonical base64url, never
issued, already spent, or outside `[issued_at, issued_at + 120 s)`); a source
over its limit is then `fetch_rate_limited`; the handle resolves to a pending,
unexpired challenge (`unknown_handle`); a credential and proof are present and
the fetcher authenticates by `CheckOrg` (`fetch_unauthenticated`); the fetcher
is the handle's person (`fetch_wrong_approver`); the proof verifies for this
broker's audience (`bad_fetch_proof`). An undecodable body is logged
`malformed`.

A consumption: the record is held (`unknown_approval`) and carries the digest
(`digest_mismatch`); a single-use record is consumed once (`approval_consumed`)
and lapses `MaxApprovalTTL` after it is given; a time-bounded one authorises
every consumption before `not_after` (`approval_expired` at it) and is never
written.
