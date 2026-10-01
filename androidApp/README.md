# androidApp — **Cruciform**, the Android authenticator

The first-party Android app, **Cruciform** (`one.rarebit.cruciform`; the Hyperion
Cantos artefact that lets you come back with your identity intact — ADR-0004): a
Jetpack Compose, Material 3, **dark-first** authenticator that drives the real
**Void-Which-Binds** protocol flows with a hardware-backed device key. Void-Which-Binds names the
protocol and the `void-which-binds:` scheme; Cruciform names this app. It is a separate Gradle application module that depends on the root KMP
library (`project(":")`) — the shared wire contract, the flow coordinators, and
the hardware `DeviceKeyStore`.

## What it does

The screens follow the product mockups one-to-one:

| Screen | Purpose |
|---|---|
| Onboarding | Create a new identity · Restore from a recovery secret · Add this device (pair) |
| Home | Identity fingerprint, StrongBox status, this device, trusted sites, Scan FAB |
| Scan | CameraX + ML Kit QR scanner → dispatches web-login vs pair invites |
| Login approval | Sovereign consent sheet for a web login, biometric-gated |
| Pair · Connect | Show the one-time encrypted invite QR (existing device) |
| Pair · Verify | Compare the 7-digit SAS out of band, then confirm |
| Recovery backup | Display + acknowledge the bech32m recovery secret (screenshots blocked) |
| Settings | Device name, biometric approval, trusted sites (revoke), recovery, about |

Two ways the app is opened *into* a login from outside its own UI, both running the
identical approval flow a scan does: a **push wake** (`UnifiedPushReceiver`, self-hosted
ntfy/UnifiedPush) and a **same-device deep link** — a relying-party app on this phone
launching `void-which-binds:login?rp=&id=[&callback=]` (`ACTION_VIEW`, the activity is
`singleTask`, so a warm app gets it via `onNewIntent`). After the deep-link decision the
activity finishes so the caller resumes; a well-formed private-scheme `callback` is
launched bare only after a successful approval. Routing lives in `handoff/`
(`HandoffRouter`, pure Kotlin, unit-tested) — see ADR-0003.

## Architecture

- **`domain/`** — UI-facing models (`Identity`, `DeviceInfo`, `TrustedSite`,
  `LoginRequest`, `PairSession`, …) and **`VoidbindEngine`**, the single seam the UI
  calls. Everything cryptographic lives behind it; screens receive already-formatted
  fingerprints and booleans and never touch key bytes.
- **`ui/theme`** — the palette (mint = security, blue = brand, amber = recovery,
  coral = destructive), typography (a monospace face for every load-bearing crypto
  string), and the dark Material 3 scheme.
- **`ui/components`**, **`ui/screens`**, **`ui/nav`** — the reusable pieces, the
  screens, and the `CruciformNavHost` that wires them with a bottom bar.
- **`ui/scan`** — the CameraX + ML Kit QR reader (`QrScanner`).

### Two engines

`VoidbindEngine` has two implementations:

- **`PreviewVoidbindEngine`** (present) — an in-memory backend seeded with the
  mockup data. It performs **no cryptography and no I/O**; it exists so the entire UI
  runs and can be reviewed against the mockups before the hardware/coordinators are
  wired. It is scaffolding, clearly labelled, and every value in it is placeholder
  content, not a real identity.
- **`DeviceVoidbindEngine`** — the real backend: `UserIdentity`
  create/restore, the hardware `DeviceKeyStore` signing key + a sealed-at-rest X25519
  encryption-key store → `DeviceIdentity`, `Enrolment.selfEnrol`, and the
  `LoginApproval` / `DevicePairing` / `DeviceAuthorization` coordinators over an
  OkHttp `HttpTransport`, with `BiometricPrompt` gating each signature.

The engine is chosen at **build time** — no source edit:

```sh
./gradlew :androidApp:assembleDebug                     # preview engine (default; CI)
./gradlew -PdeviceEngine=true :androidApp:assembleDebug # real hardware engine (device testing)
```

(`deviceEngine` → `BuildConfig.USE_DEVICE_ENGINE`; `deviceEngine=true` in
`gradle.properties` also works.) Debug builds additionally allow cleartext HTTP
(`src/debug/AndroidManifest.xml`) so a plain-http LAN test node can be used.

## Building

```sh
./gradlew :androidApp:assembleDebug            # build the debug APK (preview engine)
./gradlew :androidApp:testDebugUnitTest        # pure-JVM unit tests (deep-link routing)
```

`local.properties` must point `sdk.dir` at your Android SDK (gitignored).

### Gen2 (1.0.0+): a new identity, no gen1 state

From 1.0.0 Cruciform is **gen2-only** (void-which-binds-go ADR-0022, library 0.11.0). It
answers the `void-which-binds:` scheme alone (a gen1 `voidbind:` link never reaches it),
advertises/queries `one.rarebit.voidwhichbinds.category.RP_HANDOFF` with the
`one.rarebit.voidwhichbinds.rp.pair_scheme` meta-data, and keeps everything on the device
under fresh names: keystore aliases `void-which-binds.secret.wrap[-strong].<n>` (and the
library's `void-which-binds.wrap.<alias>`), `filesDir/void-which-binds/`, prefs
`void-which-binds.{identity,policy,notify,relay,push}`. Nothing reads the gen1
`voidbind.*` names, so installing over a gen1 build starts with no identity: reset the app
(clear its data) and enrol fresh — the cutover's phone step (ADR-0022 C2 step 8). A gen1
`heyarr1…` recovery sheet is refused with "This is an old (gen1) recovery sheet"; the gen2
sheet's secret is `void-which-binds1…` (75 characters).

### Installing over the old `one.rarebit.voidbind` package

Cruciform is a **different app** to Android from the pre-0.3.0 `one.rarebit.voidbind`
build: its keystore key and identity prefs are not carried over. Install the new
package, enrol (create / restore / pair), and only then uninstall the old one so a
single authenticator claims the (then) `voidbind:` scheme:

```sh
./gradlew -PdeviceEngine=true :androidApp:assembleDebug
adb install -r androidApp/build/outputs/apk/debug/androidApp-debug.apk   # one.rarebit.cruciform
# … launch Cruciform, enrol …
adb uninstall one.rarebit.voidbind                                          # LAST
```

## Acceptance is device-tested, not CI

CI compiles and assembles this module so a broken build cannot merge, but the
load-bearing security properties — **StrongBox non-extractability and biometric
gating** — do not exist on an emulator and are proven only on real hardware. See
[`docs/DEVICE-TESTING.md`](../docs/DEVICE-TESTING.md). Treat the Android
`DeviceKeyStore` StrongBox path and the biometric gate as *scaffolded, not verified*
until run on a physical StrongBox device.
