# 0004. The authenticator app is named **Cruciform**; **Voidbind** names the protocol

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-02
**Relates to:** ADR-0001 (hardware keystore), ADR-0003 (the `voidbind:` deep link), the
consumption-clients plan (`voidbind-client-apps-and-push.md`: ONE authenticator, N relying parties)

## Context

"Voidbind" has been doing two jobs: it is the name of the **protocol / security model**
("the void which binds" — self-sovereign device identity, no central authority, keys
pinned in secure hardware) *and* the user-visible name of the phone app that holds the
key. That overloading gets in the way as soon as relying parties talk about it: a
button that says "Sign in with Voidbind" names the mechanism, but the thing the user
installs and opens is an app, and an app needs a name that is not the name of the
wire format it speaks.

## Decision

1. **Voidbind is the protocol.** Every protocol-level identifier stays exactly as it
   is: the `voidbind:` URI scheme (`voidbind:login?…`, `voidbind:pair?…`), the library
   coordinates `one.rarebit.voidbind:voidbind-client`, the Kotlin package
   `one.rarebit.voidbind.*` for the library, the `Voidbind.xcframework` module, the
   `VoidbindQr` / `VoidbindDeepLink` / `VoidbindAndroid` / `VoidbindIos` API, the
   `voidbind-go` / `voidbind-kmp` repositories, and all ADR / wire terminology
   (including the identity-defining `heyarr/…` labels of `Labels.kt`, which are
   untouched). Relying parties keep resolving the **scheme**, not a package, so an RP
   that launches `voidbind:login?…` keeps working unchanged.

2. **Cruciform is the authenticator app** — the Hyperion Cantos artefact: the thing
   that lets you die and come back with your identity intact, which is exactly what a
   recovery secret plus a hardware-bound device key does. The rename covers everything
   a user sees or Android identifies the app by:
   - Android `applicationId` / `namespace` **`one.rarebit.cruciform`** (was
     `one.rarebit.voidbind` / `one.rarebit.voidbind.app`); the app module's Kotlin
     package is `one.rarebit.cruciform` (moved with `git mv`, not aliased).
   - Launcher label, Home / Onboarding header, Settings "About Cruciform", and the
     app-branded classes (`CruciformApp`, `CruciformTheme`, `CruciformMark`,
     `CruciformNavHost`, `Theme.Cruciform`). The engine seam stays `VoidbindEngine`
     — it is the app's driver of the Voidbind protocol, not branding.
   - The iOS scaffold's app target / display name / bundle id
     (`Cruciform`, `one.rarebit.cruciform`); the framework it links stays `Voidbind`.
   - A small **"Voidbind protocol"** attribution stays where the security posture is
     explained (Onboarding, Settings › Security & protocol), so the app never hides
     what it speaks.

3. **The identity label on Home is the device name, not a tag.** The line beside the
   identity fingerprint shows the name this device enrolled under (the user's Settings
   name, else the manufacturer/model captured at enrolment, else `This device`) — never
   the mockup-era `vb1` placeholder. The same label is what a login sheet shows under
   "Sign in as".

## Consequences

- **A new `applicationId` is a new app to Android.** An existing install of
  `one.rarebit.voidbind` is *not* upgraded in place: its AndroidKeyStore key, sealed
  enc-key and identity prefs are private to the old package and are not carried over.
  The accepted migration is: install `one.rarebit.cruciform`, enrol again (create /
  restore / pair), then uninstall the old package **last**, so that only one
  authenticator claims the `voidbind:` scheme (`docs/DEVICE-TESTING.md`).
- Relying-party **copy** that says "Voidbind" where it means the app (button labels,
  "install Voidbind" hints) should say "Cruciform"; copy that names the mechanism
  ("Voidbind sign-in", "a Voidbind code") is still correct. Those strings live in the
  RP repos (heyarr-mobile, allthing-android) and are changed there.
- The library is unchanged in API; a `v*` tag still publishes `voidbind-client`.

## What would make us revisit

- A second first-party authenticator (e.g. a desktop holder) — the protocol name would
  then be the family name and each holder its own.
