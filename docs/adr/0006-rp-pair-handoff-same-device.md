# 0006. RP pair handoff on the same device: the authenticator hands its invite to a relying-party app by the RP's own scheme

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-02
**Relates to:** ADR-0003 (the RP → authenticator `voidbind:` deep link), ADR-0005 (any member
mints a v3 invite), the consumption-clients plan (`voidbind-client-apps-and-push.md`: ONE
authenticator, N relying parties). Closes voidbind-kmp #28.

## Context

Since 0.5.0 (ADR-0005) **any member device can admit the next**: Cruciform's Settings →
Devices → *Add a device* mints a `voidbind:pair?v=3&…&usr=` invite and shows it as a QR, and
a relying-party app that holds its own sealed device key — heyarr-mobile (PR #12), All
Thing — joins that invite by scan or paste and receives its admission `{op, ops}` after the
SAS matches. That already covers the case #28 was filed for, except on **one phone**: the RP
app cannot point a camera at the screen it shares.

ADR-0003 solved the reverse direction (RP → authenticator) with a `voidbind:` deep link,
and the obvious symmetric move — firing `voidbind:pair?…` from here — is wrong: that scheme
is *ours*. Cruciform would resolve its own link and join its own invite, a loop.

#28's original sketch (a `voidbind:authorise?…` the RP fires, the authenticator holding the
USER identity, a merged SAS screen) is superseded by ADR-0005: the authenticator no longer
needs the recovery secret to admit a device, and the SAS gate already lives on the
initiator's VERIFY screen.

## Decision

1. **Cruciform opens the RP with the RP's own pair-callback URI**, carrying the invite it
   just minted as one percent-encoded query value:

   ```
   heyarr-mobile://pair?invite=<encoded voidbind:pair?v=3&relay=…&session=…&salt=…&usr=…>
   allthing://pair?invite=<…>
   ```

   The invite tuple travels **verbatim** — byte-identical to the QR (`Invite.encode`) — so
   the RP feeds it to the very same `Invite.decode` a scan would. Nothing here is a new wire
   format; the library is unchanged (still 0.5.0). Encoding is RFC 3986 percent-encoding of
   the whole tuple (`RpPairHandoff.percentEncode`, uppercase `%XX`, no `+`), so the RP
   decodes it with any standard decoder.

2. **A small app-local registry of known RP callbacks** (`handoff/RpPairHandoff.KNOWN`:
   `heyarr-mobile://pair`, `allthing://pair`), each backed by a manifest `<queries>` entry
   for package visibility. The Connect screen calls `resolveActivity` per target and shows
   **one "Send to `<app>` on this phone" button per app that resolves — none otherwise**.
   Adding an RP is one registry line plus one `<queries>` line.

3. **An Android Sharesheet fallback** ("Share invite…", `ACTION_SEND` `text/plain` of the
   tuple) for an RP we do not know or a user who prefers to paste. The invite is one-time,
   bound to a relay session that expires, and the SAS still closes a substituted invite —
   sharing the text leaks nothing a QR on screen does not.

4. **The SAS gate is unchanged and stays on Cruciform.** While the RP joins, the Connect
   screen keeps blocking on `awaitPairHandshake()` exactly as for a scan; when the RP's
   `DevicePairing.begin` completes, Cruciform advances to VERIFY with the 7-digit SAS. The
   RP shows *its* SAS large on its own screen. The human switches back (recent apps — the
   activity is `singleTask`, so the invite flow is where they left it), compares the two,
   and confirms **on Cruciform** behind the biometric prompt; only then is the admission
   sealed to the RP's X25519 key and delivered. The RP's `confirm` then unseals it. A
   mismatch is cancelled here and nothing is signed.

5. **No result channel, no callback back to Cruciform.** As in ADR-0003, the RP learns
   the outcome from the relay (`confirm`), never from an intent. Cruciform does not pass a
   return URI to the RP: the RP's job after `begin` is to *show the SAS and wait*, and the
   user's next action is on Cruciform anyway.

## Consequences

- One phone with Cruciform + heyarr-mobile enrols heyarr-mobile as a device in a single
  sitting: Add a device → Send to heyarr → heyarr shows the code → back to Cruciform →
  compare → fingerprint. No second phone, no Mac, no `pair-initiate`.
- A malicious app that squats an RP's scheme can receive an invite the user *explicitly
  sent it*. It gains the ability to *join the relay session* — which is exactly what
  anyone who photographs the QR gains — and the SAS comparison on Cruciform is what
  refuses it: the user sees a code on the wrong app, or no matching app at all, and
  cancels. Verified App Links would close even the "user sent it to the wrong app"
  window; see below.
- The registry is a whitelist by design. An unknown RP uses the Sharesheet or a scan
  from another device; it does not get a one-tap button by merely registering a scheme.

## What would make us revisit

- Android App Links (verified `https` hosts) for RP callbacks once the RPs have a domain
  to verify against — then the registry could be a list of verified hosts.
- An RP-supplied "bring Cruciform back" hint (`&return=<uri>`) if the switch back via
  recent apps proves to be the step users miss. It would be a foregrounding nicety only,
  as ADR-0003's `callback` is.
- A discovery mechanism (an RP advertising its pair callback via `<meta-data>`) if the
  registry grows past a handful of first-party apps. **Adopted in ADR-0009 (#39):** the
  hard-coded `RpPairHandoff.KNOWN` registry and per-scheme `<queries>` entries are replaced
  by a shared `RP_HANDOFF` intent category + a `pair_scheme` `<meta-data>`, so RPs
  self-advertise and Cruciform discovers them at runtime.
