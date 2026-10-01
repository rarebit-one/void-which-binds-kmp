# 0008. On one phone the SAS is compared by the apps, not by the human

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-03
**Amends:** ADR-0006 §4 and §5 (the SAS gate stays on Cruciform; no callback back to Cruciform)
**Relates to:** ADR-0003 (RP → authenticator `voidbind:` deep link), ADR-0005 (any member
mints a v3 invite), ADR-0007 (the invite outlives the screen), voidbind-kmp #41, #39.

## Context

The same-phone enrolment ADR-0006 built works, and Jaryl ran it live on 2026-09-03
(Cruciform 0.6.0 → heyarr-mobile). His verdict: *"it was a bit clumsy, having to switch
between two apps to match confirmation codes, and accept."* The dance was: Cruciform mints
→ Send to heyarr → heyarr creates its key behind a fingerprint → heyarr shows its SAS →
switch back → Cruciform shows its SAS → **compare seven digits by eye** → biometric confirm
→ switch back. Four app switches and a manual comparison.

The SAS is not decoration. Pairing is commit-before-reveal over an untrusted relay, and the
short authentication string is what a **relay man-in-the-middle** cannot forge: an attacker
who substitutes its own device key on the relay channel produces a different SAS on the two
ends, and the human comparing them across an out-of-band channel — two screens, a phone
call, the same room — is what catches it. On **two devices** there is no other channel, so
the human is the channel.

On **one phone** there is. Cruciform hands the invite to the relying party by Android
intent (ADR-0006 §1) and the RP is a process on the same device. An intent is a local
channel the relay cannot observe, reach, or modify. The out-of-band comparison the human
was performing can therefore be performed by the two apps over that channel, with the same
security property and none of the switching.

ADR-0006 §5 deliberately said "no result channel, no callback back to Cruciform" — the RP
learns its outcome from the relay, never from an intent. That remains true of the
**outcome**. What this ADR adds is not a result channel; it is the **second channel the SAS
check needs**, carrying only values that are already public and already committed to.

## Decision

1. **The RP reports what it derived, over a local intent.** Once the responder has posted
   its relay commit and derived the SAS, an RP that received the invite **by the same-phone
   deep link** (and only then) fires

   ```
   cruciform://pair-joined?session=<relay session>&dev=<its ed25519:… device key>&sas=<its SAS>
   ```

   Cruciform registers a VIEW filter for `cruciform://pair-joined`. Nothing here is
   secret: `dev` is a public key the RP already committed to on the relay, `sas` is derived
   from both sides' public keys and the invite salt, and `session` is in the invite tuple
   the RP was handed. A leak of all three grants nothing — the admission is sealed to the
   responder's X25519 key regardless.

2. **Cruciform compares; it never adopts.** The relay handshake runs to completion exactly
   as before, and the initiator learns the responder's device key from the **relay reveal**
   (`PairflowInitiator.responderDeviceId`, newly exposed — it is the key the add op is
   about to name) and derives its **own** SAS. `handoff/SamePhonePairCallback.decide` then
   compares the report against those, for the same session:

   - **match** (key equal case-insensitively, SAS equal on its digits) → the comparison is
     satisfied;
   - **not our session** → ignored; the live invite is untouched;
   - **too early** (the report beat our own relay poll) → held, and re-decided the instant
     the reveal lands — never acted on early;
   - **mismatch** → the invite **fails loudly** (`PROTOCOL`, not retryable) and nothing is
     ever signed. On one phone the only way to reach that branch is a relay that
     substituted a key.

3. **One sheet, one biometric.** On a match the graph shows `PairAllowScreen` instead of
   `PairVerifyScreen`: *"Allow **heyarr** on this phone to act as you?"* with the RP's label
   and icon, and no code anywhere on screen. Allow runs the **identical** signing path the
   SAS screen ran — `InviteCoordinator.confirm()` → biometric → the add op signed by this
   device → sealed and delivered. Only the question in front of it changed.

4. **The return trip.** After the admission is delivered Cruciform launches the RP's
   `<scheme>://pair-done?session=<id>` and finishes its own task, so the human ends up back
   in the app they started in, enrolled. It is bare — the session id only; the admission
   reached the RP sealed, over the relay. An RP that does not handle it is still enrolled;
   the user simply returns through recent apps.

5. **Cross-device is unchanged.** No callback, no second channel, so `PairVerifyScreen` and
   the human's seven digits stand exactly as ADR-0006 §4 describes. The same is true on one
   phone when the RP is an older build that never calls back, or when the invite was
   scanned or pasted rather than deep-linked: absence of a report is not a failure, it is
   the ordinary path.

6. **Who the caller is decorates the sheet; it does not decide anything.** The RP is
   identified from Android's `referrer` attribution, resolved against `RpPairHandoff.KNOWN`
   through the same `<queries>` visibility the "Send to <app>" button already needs. An
   unidentified caller whose key and SAS match is still a match, and gets a generic label.

## Consequences

- The same-phone enrolment becomes: *Add a device → Send to heyarr → one fingerprint in
  heyarr (its own key) → one biometric in Cruciform → back in heyarr, enrolled.* Two
  gestures, no code, no comparison.
- **The protocol is untouched.** Same pairflow, same commit-before-reveal, same op, same
  relay messages, same wire formats. The library gains one read-only accessor
  (`responderDeviceId`) for a value it already held.
- A malicious app that squats an RP scheme can still receive an invite the user explicitly
  sent it (ADR-0006's consequence, unchanged) — and can now also report a matching key and
  SAS, because it genuinely joined the session. That is the same position as before: the
  thing being approved is named on the sheet, and the human approves *that app*. What the
  callback removes is the human's ability to catch a **relay** MITM by eye; what replaces it
  is a comparison the same human could not have done better, made against a channel the
  relay does not sit on.
- A report that never arrives costs nothing: the flow is exactly ADR-0006's.
- The decision logic is pure Kotlin (`SamePhonePairCallback`) and unit-tested on the JVM —
  parse, session scoping, early arrival, key mismatch, SAS mismatch, formatting tolerance —
  alongside `InviteCoordinatorSamePhoneTest` for the state machine's half.

## What would make us revisit

- **#39** (RPs self-advertising through a shared intent category) would replace the
  hard-coded `KNOWN` registry and the per-scheme `<queries>` entries. The one-tap callback
  is already built from the **resolved** scheme rather than a second list, so it needs no
  change when that lands.
- If a third-party RP ever ships on this channel, binding the callback to a **verified**
  App Link (or requiring the caller package to match the package the invite was sent to)
  would close the "user sent the invite to the wrong app" window that ADR-0006 already
  names.
