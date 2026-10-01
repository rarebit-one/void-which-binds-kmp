# Cruciform iOS app

The SwiftUI device authenticator, **Cruciform** (the app; *Void-Which-Binds* is the protocol —
ADR-0004). The Xcode target is `Cruciform`, bundle id `one.rarebit.cruciform`; the
Swift sources still live under `Voidbind/`, the folder named for the framework's gen1 name. It links the KMP library as `VoidWhichBinds.xcframework`
and provides the two platform pieces the library needs on iOS: the **Swift
`SecureEnclaveSealer`** (seals the Ed25519 signing seed to a Secure-Enclave P-256
key) and a **`URLSessionHttpTransport`**. Everything else — identity derivation,
pairing, web-login, cert crypto — lives in the shared library.

## Build & run (Simulator)

The Xcode project is generated from [`project.yml`](project.yml) with
[XcodeGen](https://github.com/yonom/XcodeGen) (`brew install xcodegen`), so
`Cruciform.xcodeproj` is **not** checked in — regenerate it after a clone:

```sh
cd iosApp
xcodegen generate            # writes Cruciform.xcodeproj from project.yml
# The scheme's pre-build phase always runs `assembleVoidWhichBindsDebugXCFramework`
# (Gradle's up-to-date checks make it cheap when nothing changed, and a Kotlin edit
# is never linked stale); you can also build it up front from the repo root:
#   ./gradlew assembleVoidWhichBindsDebugXCFramework
xcodebuild -scheme Cruciform -project Cruciform.xcodeproj -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' ARCHS=arm64 EXCLUDED_ARCHS=x86_64 build
```

`ARCHS=arm64 EXCLUDED_ARCHS=x86_64` is required: Kotlin/Native only emits an
**arm64** simulator slice, so an Intel-arch simulator leg won't link. On Apple
Silicon this is the native path anyway.

Install + launch in a booted arm64 Simulator:

```sh
DEV=$(xcrun simctl list devices available | grep -m1 'iPhone 17 Pro (' | grep -oE '[0-9A-F-]{36}')
xcrun simctl boot "$DEV"
APP=$(find iosApp/build/DerivedData/Build/Products/Debug-iphonesimulator -maxdepth 1 -name Cruciform.app)
xcrun simctl install "$DEV" "$APP"
xcrun simctl launch  "$DEV" one.rarebit.cruciform
xcrun simctl io "$DEV" screenshot onboarding.png
```

Verified on the iOS 26.2 Simulator (Xcode 26.2): the app builds, installs,
launches, and renders the onboarding screen (Create / Restore).

Project facts: target + display name `Cruciform`, bundle id `one.rarebit.cruciform`, deployment target iOS 16, links
`VoidWhichBinds.xcframework` **Embed & Sign**, `NSFaceIDUsageDescription` +
`NSCameraUsageDescription` in `Info.plist`. The app's Swift module is
`CruciformApp` (not `VoidWhichBinds`) so `import VoidWhichBinds` resolves to the framework and
not the app target itself.

> ⚠️ CI verifies the KMP library (`jvmTest` + Android + the iOS klibs) and the
> Swift files are type-checked against the real exported framework. What still
> needs a **real iPhone** is the runtime Secure Enclave + biometric behaviour —
> see [`../docs/DEVICE-TESTING.md`](../docs/DEVICE-TESTING.md).
>
> To re-run the type-check:
> ```sh
> cd .. && ./gradlew assembleVoidWhichBindsDebugXCFramework
> SLICE=build/XCFrameworks/debug/VoidWhichBinds.xcframework/ios-arm64-simulator
> xcrun --sdk iphonesimulator swiftc -typecheck \
>   -target arm64-apple-ios17.0-simulator -F "$SLICE" iosApp/Voidbind/*.swift
> ```

## Files

| File | Role |
|---|---|
| `Voidbind/SecureEnclaveSealer.swift` | `EnclaveSealer` — implements the KMP `SecureEnclaveSealer` protocol (SE P-256 key + ECIES seal/unseal of the Ed25519 seed, biometric-gated; Keychain persistence). Named `EnclaveSealer` so it doesn't clash with the protocol. |
| `Voidbind/URLSessionHttpTransport.swift` | The KMP `HttpTransport` actual over `URLSession` (GET/POST/PUT/DELETE; blocking, per the contract). |
| `Voidbind/VoidbindEngine.swift` | Wiring — the iOS mirror of Android's `DeviceVoidbindEngine`: `UserIdentity` create/restore, `DeviceIdentity` provisioning, `Enrolment`, the three coordinators (+ `make*` convenience builders). |
| `Voidbind/VoidbindApp.swift` | `@main` app; builds the `AppModel` (which builds the engine + injects the sealer) once, shows `RootView`. |
| `Voidbind/AppModel.swift` | Root app state: enrolled identity (persisted), trusted sites, sign-out. |
| `Voidbind/RootView.swift` | Onboarding until enrolled, then Home. |
| `Voidbind/Theme.swift` | The dark-first / teal design language: palette, fonts, card / button / pill treatments. |
| `Voidbind/UIHelpers.swift` | QR code rendering (CoreImage) + identity-fingerprint formatting. |

### Screens (the eight mockups)

| File | Screen |
|---|---|
| `Voidbind/OnboardingView.swift` | Onboarding — create / restore / add-this-device, over the create/restore → enrol wiring. |
| `Voidbind/RecoveryBackupView.swift` | Recovery backup — the bech32m secret, shown once. |
| `Voidbind/HomeView.swift` | Home — identity fingerprint, Secure-Enclave card, trusted sites, Scan FAB. |
| `Voidbind/ScanView.swift` | QR scanner — dispatches login vs pair (AVFoundation camera; manual-entry fallback in the Simulator). |
| `Voidbind/WebLoginApprovalView.swift` | Web-login approval sheet — audience + live expiry countdown + Approve-with-Face-ID. |
| `Voidbind/PairView.swift` | Pairing — CONNECT (invite QR) and VERIFY (7-digit SAS), both sides. |
| `Voidbind/SettingsView.swift` | Settings — identity, add-a-device (recovery-secret gated), security posture, sign out. |
| `Smoke/RuntimeSmoke.swift` | A **runtime** smoke — runs the identity path from Swift in the iOS Simulator and checks the results (bridging, `@Throws`, the derivation KAT). Not part of the app target. |

Each screen is a thin View over a `VoidbindEngine` coordinator, exactly as
`OnboardingView` is; the engine work runs off the main thread (the KMP transport +
Secure Enclave are blocking) and publishes back on the main actor.

## Preview harness — screenshot any screen headless

`Voidbind/PreviewHarness.swift` (**DEBUG only**, not in the shipping `RootView`
path) renders a single screen with representative sample data, selected by the
`VOID_WHICH_BINDS_PREVIEW_SCREEN` launch environment variable — so every screen can be
built + screenshotted in the Simulator with no device, camera, Secure Enclave, or
network:

```sh
DEV=<booted arm64 simulator udid>
for s in onboarding recovery home scan login pair-connect pair-verify settings; do
  xcrun simctl terminate "$DEV" one.rarebit.cruciform 2>/dev/null
  SIMCTL_CHILD_VOID_WHICH_BINDS_PREVIEW_SCREEN=$s xcrun simctl launch "$DEV" one.rarebit.cruciform
  sleep 2; xcrun simctl io "$DEV" screenshot "$s.png"
done
```

All eight verified rendering on the iOS 26.2 Simulator (Xcode 26.2).

## Runtime smoke (no device, no UI, no network)

`Smoke/RuntimeSmoke.swift` drives the pure identity surface from Swift in the iOS
**Simulator**, so it proves the Swift↔KMP bridge works at runtime — the
`Data`↔`KotlinByteArray` conversions, the companion/object accessors, and the
`@Throws` catch — not just that the Swift type-checks. It exercises only
derivation (no Secure Enclave, no network), so it runs headless. See the header of
that file for the exact `swiftc` + `simctl spawn` commands. Verified passing on the
iOS 26.2 Simulator before the gen2 cutover (the gen2 KAT, `GEN1_REFUSED` and the
`void-which-binds:` QR are not yet re-run on a Mac):

```
ROUNDTRIP OK      # create → recovery secret → restore → same identity
KAT OK            # a known secret derives the exact void-which-binds-go public key, through Swift
THROWS OK         # a mistyped secret is caught, not a crash (the @Throws fix)
GEN1_REFUSED OK   # a gen1 heyarr1… secret is refused (ADR-0022: no gen1 reader)
QR_MATCH OK       # the void-which-binds:login QR is byte-identical through Swift
SMOKE_DONE
```

## Building the framework the app links

```sh
cd ..                                   # repo root
./gradlew assembleVoidWhichBindsReleaseXCFramework
#   → build/XCFrameworks/release/VoidWhichBinds.xcframework  (ios-arm64 + simulator)
```

## Xcode project setup (one-time, done on-device/-Mac)

There is no `.xcodeproj` checked in yet (it is generated on the machine that has
Xcode). To stand it up:

1. **New Xcode project** → iOS App, SwiftUI, name it `Cruciform`, bundle id
   `one.rarebit.cruciform`. Add the `Voidbind/*.swift` files here to the target.
2. **Link the framework**: drag `build/XCFrameworks/release/VoidWhichBinds.xcframework`
   into the target → *Frameworks, Libraries, and Embedded Content* → **Embed & Sign**.
   (Add a Run Script or a Gradle build phase to re-run `assembleVoidWhichBindsReleaseXCFramework`
   so the framework tracks the library.)
3. **Capabilities / entitlements**:
   - Face ID usage string: add `NSFaceIDUsageDescription` to `Info.plist`
     ("Authenticate to use your Cruciform device key").
   - Keychain sharing is not required (items are app-scoped, this-device-only).
4. **Signing**: a real Secure Enclave needs a device build (the Simulator has no
   Enclave — the sealer's provision/unseal only truly exercise on hardware).

## Wiring recap

```swift
// once, at startup (VoidbindApp builds this):
let engine = VoidbindEngine()                    // injects SecureEnclaveSealer into the library

// onboarding:
let identity = engine.createIdentity()           // show identity.recovery.format() ONCE
// restore instead: `let identity = try engine.restoreIdentity(secret)` — throws on a mistyped secret
let device   = engine.deviceIdentity()           // provisions the SE-sealed signing key
_ = engine.enrolFirstDevice(identity: identity, device: device)

// scan dispatch (types drop the framework prefix — VoidbindQr.Login / .Pair):
switch engine.parseScanned(qr) {
case let login as VoidbindQr.Login: /* engine.loginApproval(...).begin/approve */ break
case let pair  as VoidbindQr.Pair:  /* engine.devicePairing(...).begin/confirm */ break
default: break
}
```

Run the coordinator calls off the main thread (`Task.detached` / a background
queue) — the KMP transport is blocking, the same as Android's `Dispatchers.IO`.
