# 0005. Membership op-set: the device side of "any member admits or removes"

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-02
**Mirrors:** voidbind-go ADR-0007 (`docs/adr/0007-membership-op-set.md`, v0.9.0) — the
source of truth for the op format, the evaluation rules and the golden vectors.
**Plan:** `~/.claude-family/plans/voidbind-peer-delegation.md` (option D), §2 items 6–8.

## Context

Until v0.4.0 a Voidbind identity was one Ed25519 keypair (derived from the recovery
secret) and every device cert was signed by *that* key. In Cruciform that meant only
the device holding the sealed recovery secret could "Add a device"
(`startPairInvite` → `requireUser()`), a phone admitted by pairing could never admit
the next phone, and the secret was unsealed far more often than "recovery only" implies.

voidbind-go v0.9.0 replaced the root-only cert with a **membership op-set** (its
ADR-0007): an identity is a *set* of device keys evolved by signed add/remove ops that
any member may issue, evaluated as a state-based CRDT with remove-wins-unless-genesis
and seniority to settle concurrency. `usr` stays the genesis key so every relying
party's pin is unchanged, and a v1/v2 cert *is* a v3 add signed by genesis with no
`prev` — nothing already issued is reissued.

## Decision

This library mirrors the Go side exactly, as AGENTS.md's first rule demands:

1. **`MembershipOp`** — the v3 op token (`sign` / `verify` / `hash` / `user`), the
   same `base64url(payload).base64url(sig)` shape as the cert so the `Device
   <op>~<proof>` credential and the possession proof's `sha256(token)` binding are
   untouched. `verify` reads a v1/v2 cert as a genesis add. Signing takes an
   `Ed25519Signer` plus the signer's public key, because on a phone the device key is
   hardware-held and only ever signs.
2. **`Membership.evaluate(usr, ops, now)`** and **`Membership.merge`** — a
   line-for-line port of `enrolment.Evaluate` / `Merge`: the same four rules
   (structure, authority-in-own-closure, remove-wins-causally, seniority replay), the
   same reason strings, the same `View` shape (`members`, `removed`, `heads`,
   `accepted`, `rejected`, `ineffective`).
3. **Parity is the golden vectors, not review.** voidbind-go's
   `testdata/vectors/membership/*.json` (14 cases) are copied verbatim into
   `src/jvmTest/resources/vectors/membership/` and replayed by
   `MembershipVectorTest`, which also re-asserts the CRDT properties (every
   permutation, every random partition merged back). The vectors are never edited
   here — a change on the Go side is re-copied. `MembershipOpTest` additionally
   re-signs the `genesis-a-b` ops from the vector's test seeds and requires the exact
   Go tokens back (Ed25519 is deterministic, so one byte of payload drift fails it).
4. **`MiniJson` grows** just enough — string arrays, nested objects (`cosig`), and a
   general parser for the vector files — and stays a wire-shaped codec, not a JSON
   library.

Pairing from a member device (invite v3 with `usr`, the initiator revealing its ops,
the responder evaluating before the SAS) and Cruciform's persistence/UI follow in the
next two changes of the same arc; this ADR covers the brain.

## Consequences

- `commonMain` now carries the whole trust decision an RP makes, so a phone can
  judge an initiator's membership *before* deriving a SAS, and can present the ops it
  knows beside its credential (`Voidbind-Membership`, weblogin `ops`).
- A device that keeps stale heads cannot out-sign its own removal (seniority), and a
  removal sticks against re-adds unless genesis — the recovery secret — cites it.
- Expiry is judged at each op's own `iat` for authority and at `now` (with the
  cert's 5-minute skew rule) for membership, so a lapsed add loses membership but not
  the history of what it admitted while valid.
- The library version is 0.5.0; consumers see new API only (`Cert`, `Enrolment` and
  every existing coordinator are untouched by this change).
