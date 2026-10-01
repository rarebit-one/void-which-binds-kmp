# 0002. Per-RP approval policy + audit log: consent state around the unchanged signature

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-01
**Relates to:** ADR-0001 (hardware keystore mechanism) — this record does NOT touch the
signing/verification path it settled.

## Context

The web-login approval flow (`LoginApproval`) shows the human a consent sheet and,
only on Approve, produces a hardware-gated Ed25519 assertion the RP verifies offline.
Every login is treated identically: the full sheet, every time. That is safe but
high-friction for a relying party the user signs into constantly (their own homelab),
and it leaves **no record** of what was approved and when.

Plan Phase 3.3 asks for a **per-RP approval policy** (trust-on-first-use vs. always-ask)
and an **approval audit log**. The hard constraint: none of this may alter the crypto
path — the biometric-gated signature and its verification are load-bearing and settled
in ADR-0001. What we are adding is consent/UI/audit state that sits *around* that
unchanged signature.

Two placement questions had to be answered:

1. **Where does the policy state machine live?** `commonMain` is pure (ADR house rule:
   no platform APIs, no persistence, no deps). But the policy is protocol-agnostic pure
   logic that both platforms must share, exactly like the encodings.
2. **Where is it persisted?** `voidbind-kmp` deliberately persists nothing in the
   library — the app supplies storage (`IdentityStore` on Android, `UserDefaults` /
   Keychain on iOS).

## Decision

**The policy state machine and the audit-log types live in `commonMain`
(`one.rarebit.voidbind.policy`) as pure Kotlin; persistence is a seam the app fills, the
same split ADR-0001 uses for `DeviceKeyStore`.**

- **`ApprovalPolicy`** — a two-state enum: `AlwaysAsk` (the default, and the user-pinned
  override) and `TrustedTofu` (trust-on-first-use). A `SitePolicy` record carries the
  policy plus a `pinnedAlwaysAsk` flag and `firstTrustedAt`.
- **`ApprovalPolicyMachine`** — pure transitions, no clock/IO of its own:
  - a brand-new RP requires the consent sheet;
  - the **first successful approval** trusts the RP on first use (`TrustedTofu`);
  - a re-approval preserves the original `firstTrustedAt`;
  - **`pinnedAlwaysAsk` wins over TOFU** — a site the user pinned to always-ask is never
    silently re-trusted by a later successful login. This is the whole point of the
    "always ask" override and is the sharp edge the tests pin.
- **`ApprovalAuditEntry` + `ApprovalAuditLog`** — one immutable record per approve/deny
  decision (timestamp, rp, audience, login-id, decision, and the tapped `matchNumber`
  for a number-matching v2 login), read back newest-first. The "who did I approve, and
  when" trail.
- **`SitePolicyStore` / `ApprovalAuditLog`** are interfaces (the persistence seam);
  `commonMain` ships pure in-memory implementations for tests and previews. The app
  supplies persistent ones: Android `ApprovalPolicyStore` (SharedPreferences, the same
  line-delimited shape as `IdentityStore`'s trusted-site blob); iOS backs the manager
  with the in-memory stores for now (persisting across launches is a follow-up, matching
  the enc-key Keychain baseline).
- **`ApprovalPolicyManager`** — the app-facing coordinator binding the machine to the
  stores. The platform engines call `recordApproval` / `recordDenial` **around** the
  existing `LoginApproval.approve(...)` call; that call is byte-for-byte unchanged.

## Consequences

- **The crypto path is untouched.** `recordApproval` runs only *after* the RP accepts
  the assertion; a policy of `TrustedTofu` governs UI friction (full review vs.
  streamlined confirm), never whether a signature or its biometric gate happens. A
  denial records an audit entry and changes no trust (nothing was signed).
- **One brain, both platforms.** Android's `DeviceVoidbindEngine` and iOS's `AppModel`
  drive the *same* `ApprovalPolicyManager`; TOFU and the audit log behave identically,
  and the state machine is unit-tested once in `commonTest` with no device or network.
- **Trust is auditable and reversible.** Revoking a site forgets its policy; past audit
  entries are immutable and survive. The audit log is bounded (a ring) so it cannot grow
  without limit.
- **`AlwaysAsk` is a real override, not cosmetic.** Because the pin blocks TOFU, a user
  who wants to review a site every time keeps that guarantee even as they keep signing in.

## What would make us revisit

- A need for **more than two** policy states (e.g. per-scope or time-boxed trust) — the
  enum + `SitePolicy` record is the seam to extend.
- Cross-device sync of policy/audit (today each device's trail is local) — would need a
  replicated store behind the same interfaces, not a change to the machine.
- iOS persistence hardening (Keychain-sealed policy/audit), tracked as the follow-up
  above.
