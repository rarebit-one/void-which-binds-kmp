# 0003. Same-device app-to-app handoff: a `voidbind:` deep link is a third delivery channel for the QR tuple

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-02
**Relates to:** ADR-0002 (per-RP approval policy), voidbind-go `weblogin` (the tuple wire), the
consumption-clients plan (`voidbind-client-apps-and-push.md`: ONE authenticator, N relying parties).
*Naming note (ADR-0004):* "the authenticator" below is the app now named **Cruciform**
(`one.rarebit.cruciform`); "Voidbind" names the protocol and the `voidbind:` scheme, which is
what relying parties resolve — the package name is not part of the contract.

## Context

A relying-party app running on the **same phone** as the authenticator — heyarr-mobile,
allthing-android — has no way to log in today except rendering the broker's
`voidbind:login?rp=<origin>&id=<id>` QR and asking the user to scan it *with a second
phone*. That is the WhatsApp-Web pattern misapplied: the camera channel exists to bridge
two devices, and here there is only one.

The Singpass model for this case is **app-to-app**: the RP opens the authenticator, the
authenticator approves in its own UI, and the RP is resumed. Voidbind already has the
invariant that makes this cheap: the QR carries **only** the public `(rp, id)` tuple, and
the phone *pulls* the real challenge from the RP over TLS and signs it hardware-gated
after an explicit human tap. The push wake (ADR in `PushPing`) already exploits this —
a ping is "the tuple delivered by a wake signal instead of a camera". A deep link is the
same thing delivered by an `ACTION_VIEW` intent.

## Decision

1. **The authenticator registers an `ACTION_VIEW` / `BROWSABLE` intent-filter for the
   `voidbind` URI scheme** (`androidApp/AndroidManifest.xml`) and treats an incoming
   `voidbind:login?…` / `voidbind:pair?…` exactly as a scan of that string:
   `VoidbindQr.parse` → `LoginApproval.begin` (fetch challenge, show the RP origin,
   number-match grid if the challenge is v2) → human tap → biometric → hardware sign →
   `approve`. **Nothing in the link can approve anything.** A `voidbind:pair?…` link
   joins as the *new* device (`DevicePairing`), the only role the library supports for
   a *received* invite — the same as scanning it.

2. **The link is the QR tuple plus one authenticator-local key**, `callback`:

   ```
   voidbind:login?rp=<origin>&id=<login-id>[&callback=<private-app-scheme-uri>]
   voidbind:pair?v=2&relay=&session=&salt=<hex>[&callback=<private-app-scheme-uri>]
   ```

   The tuple stays byte-identical to voidbind-go's `weblogin.EncodeLogin` /
   `pairflow.EncodeInvite`; an RP builds the link from the `qr` string its broker
   already returned (`VoidbindDeepLink.loginUriFromTuple(tuple, callback)` in `commonMain`).
   `callback` is never signed, never sent to the RP server, and is stripped before the
   tuple reaches the engine.

3. **Return-to-caller is by finishing the activity.** The authenticator is `singleTask`;
   a deep link lands in `onCreate` (cold) or `onNewIntent` (warm), and after the human
   decides — or the login cannot be shown — the activity `finishAndRemoveTask()`s, so the
   caller's task resumes. The RP learns the outcome **only** by polling its own broker
   (`GET /login/{id}`), as it already does for the QR path.

4. **`callback` is a UX nicety, not a result channel.** If present *and* well-formed
   (`VoidbindDeepLink.isWellFormedCallback`: a private app scheme — not `http(s)`,
   `javascript`, `file`, `content`, `intent`, `android-app`, `voidbind`, … — no
   whitespace/control characters, ≤ 2048 chars) it is launched **bare**, with nothing
   appended, and **only after a successful approval** (never on deny/failure). A
   malformed callback is silently dropped and the approval proceeds without it. A
   missing handler (`ActivityNotFoundException`) is logged and ignored.

5. **The URI is untrusted input from another app.** It is parsed with the same strict
   parsers a scan uses; no field is interpolated into any request other than `rp` (the
   challenge fetch target, which the user sees on the approval sheet before approving,
   and which the per-RP policy of ADR-0002 applies to unchanged). `FLAG_SECURE` handling
   is untouched — the deep link reuses the existing screens.

6. **Engine selection moves to build time.** `-PdeviceEngine=true` sets
   `BuildConfig.USE_DEVICE_ENGINE`; the preview engine stays the default for CI, so the
   real hardware path can be built without a source edit.

## Consequences

- heyarr-mobile / allthing-android on the same phone can log in with one tap-through
  instead of a second device. Both still keep the QR for the cross-device case; push
  stays the default for the "approve on my phone what I'm doing elsewhere" case. Three
  channels, one mechanism.
- A malicious app on the phone can *open* the approval sheet for an RP of its choosing
  — exactly as it could show the user a QR to scan. It gains nothing: the user sees the
  origin, must tap and pass biometrics, and the signature goes to the RP, not the caller.
  The visual origin-binding a QR gave is replaced by the origin line on the sheet (for
  v1) or by number-matching (v2), same as push.
- The callback is a **foregrounding hint**, so an RP must not rely on it: the user may
  deny, the handler may be absent, or the callback may be dropped. Poll the broker.
- Debug builds allow cleartext HTTP (`androidApp/src/debug/AndroidManifest.xml`) so a
  LAN test node such as `http://192.168.x.x:7777` can be exercised during device
  testing; release builds keep the platform default.

## What would make us revisit

- Android App Links / iOS Universal Links as the RP callback (verified `https`
  callbacks) once the RPs have a domain to verify against — the deny-list would then
  admit `https` for *verified* hosts only.
- An in-process result channel (`startActivityForResult`-style) if an RP ever needs
  the outcome without a broker poll; today none does and the broker poll keeps the
  authenticator out of the result path by design.
