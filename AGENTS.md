# AGENTS.md — void-which-binds-kmp

Agent router for **void-which-binds-kmp**, the Kotlin Multiplatform **device authenticator**
side of Voidbind. Human docs: `README.md`; ADRs: `docs/adr/`; agent notes: `docs/agents/`.

## What this is

Void-Which-Binds is a device-authentication protocol extracted from **heyarr**. There are
two sides:

- **`void-which-binds-go`** — the counterpart, already built. It holds the **wire
  contract** (token formats, key rendering, recovery encoding, pairing transcript).
  It is the source of truth.
- **`void-which-binds-kmp`** (this repo) — the on-device authenticator for **iOS and
  Android**, plus a JVM target for dev/test. Its job is to hold the device signing
  key in **hardware** (Secure Enclave / StrongBox) and speak the same wire format
  as void-which-binds-go.

## Naming: Void-Which-Binds is the protocol, Cruciform is the app

> **Renamed at 0.10.0 (void-which-binds-go ADR-0013 R1); gen2-only at 0.11.0
> (ADR-0022, matching void-which-binds-go v0.19.0).** 0.10.0 moved the packaging (the
> repo, the Kotlin package `one.rarebit.voidwhichbinds`, the Maven coordinates
> `one.rarebit.voidwhichbinds:void-which-binds-client`, the `VoidWhichBinds`
> XCFramework). 0.11.0 moved every library-owned wire and device-local string to its
> gen2 spelling (the table below, the `void-which-binds:` scheme, invite `v=4`,
> `void-which-binds.*` typ, the `Void-Which-Binds-Membership` header, the Android
> keystore alias and key dir) and refuses gen1 material: there is no dual parsing and
> no gen1 reader. Class names (`VoidbindDeepLink`, `VoidbindQr`, `VoidbindEncryption`,
> `VoidbindCertSealer`, `VoidbindAndroid`, `VoidbindIos`) keep their prefix, as Go
> kept its package names. The remaining gen1 strings are the Cruciform app's
> (`androidApp/`, `iosApp/`: `one.rarebit.voidbind.category.RP_HANDOFF`, its
> keystore aliases, prefs, dirs, keychain service and copy), moved by the app's own
> gen2 change.

**Void-Which-Binds** names the protocol / security model and everything on the wire (the
`void-which-binds:` scheme, `one.rarebit.voidwhichbinds:void-which-binds-client`, the library package,
the ADR terminology). **Cruciform** names the first-party authenticator app
(`androidApp/`, package + applicationId `one.rarebit.cruciform`; the iOS scaffold
target) — see ADR-0004. Do not rename protocol identifiers to Cruciform, and do not
brand the app "Voidbind" again; a small "Voidbind protocol" attribution where the
security posture is explained is the intended overlap.

## The single most important rule: mirror void-which-binds-go exactly

Every value that crosses the wire must be **byte-identical** to what void-which-binds-go
produces/accepts. This library re-implements the *encodings* in pure Kotlin; it
does not get to invent them. When in doubt, the Go side wins — port from it, don't
design fresh.

### Identity-defining constants — DO NOT rename or "tidy"

These live in [`Labels.kt`](src/commonMain/kotlin/one/rarebit/voidwhichbinds/Labels.kt).
Changing any string silently derives different keys / incompatible tokens. It is a
total break, not a cosmetic edit. These are the gen2 spellings (void-which-binds-go
ADR-0013's table, ADR-0022); the gen1 `heyarr`/`voidbind` values are retired and
refused, never read.

| Constant | Value | Role |
|---|---|---|
| HKDF label | `void-which-binds/recovery/v1/user-identity-ed25519-seed` (`Labels`) | derives the user identity Ed25519 seed from the recovery secret |
| Recovery HRP | `void-which-binds` (`Labels`) | bech32m human-readable-part for the recovery secret (75 chars); a gen1 `heyarr1…` secret is `RecoverySecret.GenerationRetiredException` |
| User fingerprint label | `void-which-binds/user-fingerprint/v1` (`UserFingerprint`) | domain tag of the printable user fingerprint (void-which-binds-go ADR-0010); pinned by `vectors/recovery/` |
| Pairing domains | `void-which-binds/pairing/{commit,sas}/v2` (`Pairing`) | pairing transcript domain separation |
| Space-key wrap label | `void-which-binds/space-key-wrap/v1` (`VoidbindEncryption`) | HKDF info of the sealed space key (cert delivery, offload unwrap) |
| Cosig domain | `void-which-binds-cosig-v1\u0000` (`MembershipOp.cosigDomain`) | prefix of a co-signature preimage (ADR-0008) |
| Web-login domains | `void-which-binds/weblogin/challenge/{v1,v2}` (`WebLogin`) | login-assertion preimage |
| Refusal session label | `void-which-binds/pairflow/refusal/session/v1` (`PairRefusal`) | binds a pairing refusal to its session |
| `typ` | `void-which-binds.{cert,possession,op,grant,pair-refusal}` (`TokenType`) | token kind; untyped tokens are refused |

### Algorithms (fixed)

- **Identity / signing** = **Ed25519**, rendered `ed25519:<hex>`.
- **Device encryption** = **X25519**, rendered `x25519:<hex>`.
- Key rendering is always `<alg>:<lowercase-hex>` — a bare hex key is invalid.

### Wire formats

Full detail (field orders, `typ`, pairing): [`docs/agents/wire-formats.md`](docs/agents/wire-formats.md).

- Token `base64url` is URL-safe, **no padding** (Go's `RawURLEncoding`), and payload
  JSON is **compact** with fields in the exact documented order (signed as-is).
- The golden vectors in `src/jvmTest/resources/vectors/` are copied from
  void-which-binds-go and must replay byte-for-byte — never edit them here, re-copy from Go and bump
  `src/jvmTest/resources/vectors/VOID_WHICH_BINDS_GO_REF`; the `vector-drift` CI job
  (`scripts/check-vector-drift.sh`) fails on any difference.
- **Recovery secret** = 256-bit, **bech32m** (BIP-350, *not* bech32) with HRP
  `void-which-binds`.

## The hardware keystore is the whole point

`DeviceKeyStore` is an `expect class` whose signing key must be **non-extractable
at rest**: each hardware `actual` keeps a software Ed25519 seed sealed by a hardware
wrapping key (Secure Enclave / StrongBox or TEE), per
[ADR-0001](docs/adr/0001-hardware-keystore-mechanism.md); per-platform detail is in
[`docs/agents/hardware-keystore.md`](docs/agents/hardware-keystore.md).
Never ship the JVM keystore as production signing.

## Architecture invariant: `commonMain` is platform-free

`commonMain` contains **no platform APIs** (`java.*`, `android.*`, Foundation).
Its one third-party dependency is **cryptography-kotlin** (`cryptography-core` +
`cryptography-provider-optimal`, 0.6.0), which supplies SHA-256, HKDF, Ed25519 and
X25519 on every target by delegating to vetted platform primitives (JDK on
JVM/Android, CryptoKit on Apple). The wire **encodings** stay hand-written and
dependency-free (`src/commonMain/kotlin/one/rarebit/voidwhichbinds/crypto/`), so the signed/encoded bytes are fully under our control.
Platform behaviour is reached through seams (signer/verifier, AEAD, `DeviceKeyStore`,
`HttpTransport`), listed in [`docs/agents/commonmain-seams.md`](docs/agents/commonmain-seams.md).

Platform code (`jvmMain`, `androidMain`, `iosMain`) supplies the `actual`s. Do not
reach for `java.*` / platform APIs from `commonMain`, and do not add further
third-party deps there without a reason as strong as cryptography-kotlin's.

## Build & test

Host toolchain: **JDK 21** (bytecode targets JVM 17); use the wrapper (`./gradlew`),
not a system `gradle`/`kotlin`. Versions live in `gradle/libs.versions.toml`; Kotlin
is pinned by cryptography-kotlin's metadata. Android needs an SDK (`ANDROID_HOME`);
iOS targets compile only on **macOS**. Details: `docs/agents/build-and-test.md`.

```sh
./gradlew jvmTest                          # primary: compiles + runs common + JVM tests
./gradlew compileReleaseKotlinAndroid      # Android library compile (needs the SDK)
./gradlew :androidApp:assembleDebug :androidApp:testDebugUnitTest   # Cruciform app
./gradlew compileKotlinIosSimulatorArm64 iosSimulatorArm64Test      # iOS (macOS only)
./gradlew assembleVoidWhichBindsXCFramework      # → build/XCFrameworks/{debug,release}/VoidWhichBinds.xcframework
./gradlew ktlintCheck detekt              # lint (baselined: only NEW findings fail)
```

CI (`.github/workflows/test.yml`) runs all of the above except the XCFramework assembly. Lint findings
that predate the linters are baselined in `config/ktlint/baseline.xml` /
`config/detekt/baseline.xml`; fix new findings rather than regenerating the
baselines. Go-vector byte comparisons only hold where Ed25519 signing is
deterministic (not CryptoKit on iOS).

Published as `one.rarebit.voidwhichbinds:void-which-binds-client` (GitHub Packages) by
`.github/workflows/publish.yml` on a `v*` tag, which must equal `version` in `build.gradle.kts`. The
Cruciform APK is released separately on `app-v*` tags (`.github/workflows/release.yml`).

Annotated source map: [`docs/agents/layout.md`](docs/agents/layout.md).

