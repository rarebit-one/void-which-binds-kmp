# void-which-binds-kmp

> **0.11.0 is gen2-only (void-which-binds-go v0.19.0, ADR-0022) — a breaking wire
> change.** Every gen1 string now has its ADR-0013 gen2 spelling and gen1 material is
> refused, never dual-parsed: `typ` is `void-which-binds.*` and untyped tokens are
> refused; the signature domains and the recovery, space-key-wrap and fingerprint
> labels moved to `void-which-binds/…` (the same recovery secret now derives a
> **different** identity); the recovery HRP is `void-which-binds` (a `heyarr1…`
> secret throws `RecoverySecret.GenerationRetiredException`); the URI scheme is
> `void-which-binds:` with invite `v=4`; the membership header is
> `Void-Which-Binds-Membership`. Gen2 is a new identity on every device: there is
> no gen1 reader here, and the Android keystore alias / key dir are fresh
> `void-which-binds.*` names. Class names still keep their `Voidbind` prefix. The
> RP-handoff category, its meta-data key and Cruciform's own aliases/prefs are app
> strings, not library ones; they move with the gen2 Cruciform build.

<!-- k0:keep-begin readme -->
> **Renamed (void-which-binds-go ADR-0013 R1).** Voidbind is now
> **Void-Which-Binds**. From **0.10.0** this repo is `rarebit-one/void-which-binds-kmp`
> (the old URL redirects), the Maven coordinates are
> `one.rarebit.voidwhichbinds:void-which-binds-client` (0.9.0 and earlier stay
> resolvable as `one.rarebit.voidbind:voidbind-client`), the Kotlin package is
> `one.rarebit.voidwhichbinds`, and the iOS framework is `VoidWhichBinds.xcframework`.
> Nothing on the wire changed: tokens, labels, the `heyarr` HRP, headers, the
> `voidbind:` scheme and the golden vectors are byte-identical to 0.9.0; gen2
> strings arrive with 0.11.0 (ADR-0022).
>
> - **Class names keep their prefix** (`VoidbindDeepLink`, `VoidbindQr`,
>   `VoidbindAndroid`, `VoidbindIos`, …), as Go kept its package names, so a
>   consumer only rewrites `one.rarebit.voidbind.` → `one.rarebit.voidwhichbinds.`
>   in Kotlin sources, the dependency line, and its GitHub Packages
>   `includeGroup`.
> - **Do not rewrite manifests:** `one.rarebit.voidbind.category.RP_HANDOFF` and
>   the `one.rarebit.voidbind.rp.pair_scheme` meta-data key are gen1 handoff
>   strings Cruciform matches on.
> - **Cruciform** (`one.rarebit.cruciform`) keeps its keystore aliases, prefs,
>   dirs, keychain service and on-screen copy until gen2 re-enrols every device.
<!-- k0:keep-end -->

Void-Which-Binds — the **Kotlin Multiplatform device-authenticator library**: hardware-backed
device keys, commit-before-reveal pairing, and account recovery, sharing **one
wire contract** with [`void-which-binds-go`](https://github.com/rarebit-one/void-which-binds-go).
The first-party authenticator **app** built on it is **Cruciform**
([`androidApp/`](androidApp/README.md), [`iosApp/`](iosApp/README.md)) — *Void-Which-Binds*
names the protocol and the `void-which-binds:` scheme, *Cruciform* names the app
([ADR-0004](docs/adr/0004-authenticator-named-cruciform.md)).

Void-Which-Binds is a device-authentication protocol extracted from **heyarr**.
`void-which-binds-go` holds the wire contract (the source of truth); this repo is the
on-device side for **iOS / Android** (plus a JVM target for dev/test), and its
reason to exist is keeping the device signing key **non-extractable in the secure
element** (Secure Enclave / StrongBox).

## Status

In use. `void-which-binds-client` is published (0.11.0 is the gen2-only release;
0.12.0 adds Phase 3 and the space-key chain) and consumed by heyarr-kmp. All
three targets are real. **Android** seals the Ed25519 seed with a StrongBox/TEE
AndroidKeyStore key. **iOS** seals it with a Secure-Enclave P-256 key through the
app-provided Swift `SecureEnclaveSealer`. **JVM** is software-only, for dev/test.
The Cruciform Android app ships as signed release APKs (see "Releases" below). The
iOS app is a SwiftUI scaffold (see [`iosApp/`](iosApp/README.md)).

## What's here

Pure-Kotlin (`commonMain`) re-implementations of the void-which-binds-go wire types. They
use no platform APIs. The only third-party dependency is
[cryptography-kotlin](https://github.com/whyoleg/cryptography-kotlin), for SHA-256,
HKDF, Ed25519 and X25519. The encodings themselves are hand-written:

- **`RecoverySecret`** — 256-bit account secret as **bech32m** (HRP `void-which-binds`;
  a gen1 `heyarr1…` secret is refused as retired).
- **`Cert`** — enrolment cert token `base64url(json).base64url(sig)`, payload
  `{v, typ, usr, dev, denc, iat, exp}` (`typ` = `void-which-binds.cert`), signed by
  the user identity Ed25519 key.
- **`Pairing`** — short-authentication-string derivation with **commit-before-reveal**.
- **`Invite`** — the pairing QR `void-which-binds:pair?v=4&relay=&session=&salt=<hex>&usr=<ed25519:hex>`;
  `encode` is byte-identical to void-which-binds-go's `pairflow.EncodeInvite`.
- **`LoginQr` / `VoidbindQr`** — the web-login QR `void-which-binds:login?rp=&id=`
  (byte-identical to void-which-binds-go's `weblogin.EncodeLogin`), and a single
  `VoidbindQr.parse` the Scan screen calls to dispatch a scanned code to the
  login-approval or pairing flow.
- **`VoidbindDeepLink`** — the **same-device app-to-app handoff** URI (ADR-0003): the
  QR tuple plus an optional `callback=<private-app-scheme-uri>`, for a relying-party
  app on the SAME phone to open the authenticator instead of showing a QR. See
  "Same-device handoff" below.
- **`KeyRef`** — `ed25519:<hex>` / `x25519:<hex>` key rendering.
- **`auth/`** — the **`Device` authorization scheme** a relying party's API accepts
  from an enrolled device: `PossessionProof` (byte-exact port of void-which-binds-go
  `enrolment.SignPossession`/`VerifyPossession`), `DeviceCredential`
  (`Authorization: Device <cert>~<proof>` with a reuse window + `refresh()`), and
  `DeviceAuthPolicy` (re-mint and retry once on `401`, transport-agnostic). See
  "Presenting a device credential" below.
- **`DeviceKeyStore`** — `expect class` for the hardware signing key (Secure
  Enclave on iOS, StrongBox on Android; software-only on the JVM, for tests).

### Network clients (`net/`)

The wire types above plus an `HttpTransport` seam drive the live void-which-binds-go
services. A platform supplies the engine: `JdkHttpTransport` (in `jvmMain`) backs
the JVM and the tests, and the apps bring their own (OkHttp on Android,
`URLSessionHttpTransport` on iOS):

- **`RelayClient`** — the dumb pairing relay (`POST /v1/sessions`, `PUT`/`GET`
  `/v1/sessions/{id}/{role}/{type}`); `fetch` polls the peer slot.
- **`PairflowInitiator` / `PairflowResponder`** — the commit-before-reveal
  handshake with the human gate (`handshake()` returns the SAS and signs nothing;
  `authorise` / `receive` move the cert). The X25519 cert **seal** is
  `VoidbindCertSealer` (the default), completing the sealed cert delivery.
- **`VoidbindCertSealer` / `crypto.VoidbindEncryption`** — the ephemeral-static
  X25519 ECDH seal + XChaCha20-Poly1305, byte-identical to void-which-binds-go/encryption
  (`Seal`/`Unwrap`/`EncryptChange`/`DecryptChange`). Pure-Kotlin X25519 (a
  TweetNaCl port, so `unwrap` can derive the recipient public key the JDK X25519
  provider will not) + a hand-written HChaCha20 over cryptography-kotlin's IETF
  ChaCha20-Poly1305 and HKDF. Pinned by RFC vectors and a **live void-which-binds-go
  KAT** (`CertSealerCryptoTest.goSealKat`: Kotlin unwraps + decrypts a blob that
  Go sealed, to the exact bytes).
  `sealSpaceKey`/`openSpaceKey` (void-which-binds-go v0.26.0 `SealSpaceKey`/`OpenSpaceKey`)
  seal one space key under another: a link of a rotated space's key history (heyarr
  ADR-0103), `nonce(24) ‖ XChaCha20-Poly1305` with the associated data
  `void-which-binds/space-key-chain/v1`, exactly 72 bytes; every bad blob is the one
  opaque `VoidbindEncryption.UnwrapException`. Pinned by `vectors/key-chain/`
  (`KeyChainVectorTest`).
- **`WebLoginClient`** — the QR web-login: device side (`fetchChallenge`,
  `approve` with a `WebLogin.signAssertion` assertion) and browser side
  (`createLogin`, `poll`).

These are **proven against a live void-which-binds-go** in `GoInteropTest` (JVM): two
Kotlin sides pair through the real Go relay (SAS matches), and a Kotlin device
approves a login on the real Go RP, which verifies the Kotlin-signed cert and
assertion and mints a token. That test builds + runs the `void-which-binds` CLI, so it is
skipped (not failed) when `go`/the void-which-binds-go checkout is absent — CI keeps the
in-JVM mock coverage in `NetworkClientsTest`.

### Identity & enrolment

The app-facing spine that turns a recovery secret into a usable identity — the
part an onboarding screen ("Create a new identity" / "Restore from recovery
secret") drives:

- **`UserIdentity`** — `create()` mints a fresh identity (returns the
  `RecoverySecret` to back up once); `restore(secret)` reconstructs it, failing
  **loud** on a mistyped secret. The user key is derived byte-identically to
  void-which-binds-go's `recovery.DeriveUserSeed`
  (`HKDF-SHA256(secret, info="void-which-binds/recovery/v1/user-identity-ed25519-seed")`),
  and its **public half** is recovered with a pure-Kotlin Ed25519
  (`crypto.Ed25519Group`, a TweetNaCl port) **because neither the JDK nor Apple
  will derive an Ed25519 public key from a seed** — proven against a
  live void-which-binds-go KAT and cross-validated against Go stdlib + OpenSSL.
- **`DeviceIdentity`** — this device's key material: the hardware Ed25519 signing
  key (a public key + a `sign` function, from `DeviceKeyStore`) and its X25519
  encryption keypair (`generateEncryptionKey()`; sealed at rest by the app).
- **`Enrolment.selfEnrol`** — the first device self-signs its enrolment cert with
  the user key (the bootstrap case; a *second* device instead pairs over the relay).

### App-flow coordinators (`flow/`)

The thin, testable "brain" each app screen binds to — a `begin → show the human a
SAS/audience → confirm` shape around the human gate, wrapping the network clients
above. UI (Compose / SwiftUI) stays a thin view over these; run them off the main
thread (they block on the relay / network).

- **`LoginApproval`** — approve a browser web-login. `begin(qr)` fetches the
  challenge and returns what the approval sheet shows (rp, audience, expiry);
  `approve(request)` signs it with the device key (biometric-gated) and submits.
- **`DevicePairing`** — the NEW device joining. `begin(inviteQr)` runs the
  handshake and returns the SAS; `confirm(handshake)` (after the human matches the
  SAS) unseals + verifies the delivered cert and returns the token to persist.
- **`DeviceAuthorization`** — the EXISTING device adding a new one (mirror of
  `DevicePairing`). `invite(relayBase)` renders the invite QR; `handshake` returns
  the SAS; `authorise` signs + seals + delivers the cert.

These are proven against each other AND, in `CoordinatorGoInteropTest`, against a
**live void-which-binds-go** (a coordinator-driven login on the real Go RP; the two
pairing coordinators through the real Go relay).

Crypto backends (Ed25519, the pairing hash) are reached through interface seams so
the encodings stay backend-free and portable.

Identity/signing = **Ed25519**; device encryption = **X25519**. Certain constants
(the HKDF label, the `void-which-binds` HRP, the pairing labels) are **identity-defining** —
see [`AGENTS.md`](AGENTS.md); changing them silently breaks wire compatibility.

## Consuming `void-which-binds-client` as a dependency

The shared client — everything above (the `commonMain` identity/net/flow wire
brain: `UserIdentity`, `DeviceIdentity`, `Enrolment`, `RelayClient`,
`WebLoginClient`, `NotifyClient`, `PairflowInitiator`/`PairflowResponder`,
`VoidbindCertSealer`, the `LoginApproval`/`DevicePairing`/`DeviceAuthorization`
coordinators, `LoginQr`/`WebLogin` + the challenge-v2 number-match), **plus** the
`DeviceKeyStore` hardware seam — is published as a Kotlin Multiplatform artifact so
relying-party apps depend on it over the wire instead of re-implementing the login
seam.

- **Coordinates:** `one.rarebit.voidwhichbinds:void-which-binds-client:0.10.0` (Gradle resolves
  the right variant per target: `-jvm`, `-android`, `-iosarm64`,
  `-iossimulatorarm64`).
- **Registry:** GitHub Packages — `https://maven.pkg.github.com/rarebit-one/void-which-binds-kmp`
  (private; a read requires a token with `read:packages`).
- **Published by CI** on a `v*` tag / GitHub Release (`.github/workflows/publish.yml`).
  The tag must equal `version` in `build.gradle.kts` (`v0.10.0` ↔ `0.10.0`), and the
  JVM + iOS-simulator tests run before anything is published.

### What the artifact does NOT carry (stays per-app)

The published module is the shared **wire/flow brain**. The **per-platform
hardware wiring** stays in each consuming app, because it needs app-owned objects
the library cannot hold:

- **Android** — call `VoidbindAndroid.init(applicationContext)` once (e.g. in
  `Application.onCreate`) and drive the biometric gate (`BiometricPrompt`) around
  `DeviceKeyStore`/the flow coordinators. The StrongBox/TEE seal itself is in the
  artifact (`androidMain`); the `Context` + prompt are yours, and so is the
  `androidx.biometric` dependency (the library does not pull it in).
- **iOS** — implement the `SecureEnclaveSealer` protocol in Swift (CryptoKit /
  Security) and inject it once via `VoidbindIos.shared.doInit(sealer:)`. (iOS apps
  typically link the `VoidWhichBinds.xcframework` — see below — rather than the Maven
  artifact.)

### Gradle setup (consuming app)

```kotlin
// settings.gradle.kts — add the GitHub Packages repo
dependencyResolutionManagement {
    repositories {
        google(); mavenCentral()
        maven {
            // The owner-wide path resolves a package from any repo in the org, so a
            // repo rename never moves it (heyarr-kmp#114, allthing-android#20).
            url = uri("https://maven.pkg.github.com/rarebit-one/*")
            credentials {
                username = providers.gradleProperty("gpr.user").orNull
                    ?: System.getenv("GITHUB_ACTOR")
                password = providers.gradleProperty("gpr.token").orNull
                    ?: System.getenv("GITHUB_TOKEN")   // a PAT with read:packages
            }
            content { includeGroup("one.rarebit.voidwhichbinds") }
        }
    }
}
```

```kotlin
// app/build.gradle.kts — the single dependency line that replaces the login seam
implementation("one.rarebit.voidwhichbinds:void-which-binds-client:0.10.0")
```

Adding this lets `allthing-android` / `heyarr-mobile` **delete their thin
wire-compatible `login/` seam** and call the real `WebLoginClient` / `LoginQr` /
`LoginApproval` directly.

### Same-device handoff (app-to-app deep link)

An RP app running on the **same phone** as the Void-Which-Binds authenticator does not need a
second phone to scan its QR. It launches the authenticator with the same tuple its
broker returned, and resumes when the authenticator finishes (the Singpass
app-to-app model — ONE authenticator, N RPs). The contract:

```
void-which-binds:login?rp=<origin>&id=<login-id>[&callback=<private-app-scheme-uri>]
void-which-binds:pair?v=4&relay=&session=&salt=<hex>&usr=<ed25519:hex>[&callback=<private-app-scheme-uri>]
```

- The tuple is **exactly** the `qr` string from `POST /login` (byte-identical to
  void-which-binds-go's `weblogin.EncodeLogin`); `callback` is the only addition.
- The authenticator runs its normal approval: fetches the challenge from `rp`, **shows
  the origin** (and the number-match grid for a v2 challenge), and signs hardware-gated
  only after the user taps Approve + biometrics. **A deep link can never auto-approve.**
- After the user decides, the authenticator **finishes** so the RP's task resumes. The
  RP learns the outcome **only** by polling its broker (`GET /login/{id}`) — nothing
  about the login is ever passed back through the link.
- `callback`, if present and well-formed (a private app scheme — not `http(s)`,
  `javascript`, `file`, `content`, `intent`, `void-which-binds`), is launched **bare**, only
  after a **successful** approval, so the RP can foreground itself. Treat it as a hint:
  it is dropped if malformed, never launched on deny, and ignored if no app handles it.

Build the URI with the helper so the wire is never re-encoded by hand:

```kotlin
// RP app (Android), after POST /login returned {id, qr}:
val uri = VoidbindDeepLink.loginUriFromTuple(qr, callback = "heyarr://login/done")
startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(uri)))   // then keep polling GET /login/{id}
// (the authenticator is not installed → ActivityNotFoundException: fall back to showing the QR)
```

`VoidbindDeepLink.pairUri(inviteTuple, callback)` does the same for a pairing invite
(the authenticator joins as the **new** device — the same role as scanning the invite).
See [`docs/adr/0003-app-to-app-deeplink-handoff.md`](docs/adr/0003-app-to-app-deeplink-handoff.md).

The **reverse** direction — Cruciform hands the invite it minted ("Add a device") to an RP
app on the same phone — uses the RP's *own* scheme, `heyarr-mobile://pair?invite=<encoded
void-which-binds:pair tuple>` / `allthing://pair?invite=…`, from a small app-side registry
(`androidApp/…/handoff/RpPairHandoff.kt`), with a Sharesheet fallback; the SAS is still
confirmed on Cruciform. See [`docs/adr/0006-rp-pair-handoff-same-device.md`](docs/adr/0006-rp-pair-handoff-same-device.md).

On ONE phone that comparison is then made **by the apps, not by the human**: the RP reports
what it derived back over a local intent, `cruciform://pair-joined?session=&dev=&sas=`, and
Cruciform checks it against what the relay revealed for the same session. Match → one sheet
("Allow *heyarr* on this phone to act as you?") behind the biometric, no code on screen, and
the RP's `<scheme>://pair-done?session=` afterwards to land the user back where they started;
mismatch → the pairing fails and nothing is signed. **Cross-device pairing keeps the 7-digit
SAS** — there is no second channel there. See
[`docs/adr/0008-same-phone-one-tap-pairing.md`](docs/adr/0008-same-phone-one-tap-pairing.md).

### Presenting a device credential

Once a device is enrolled it calls a relying party's API (heyarr's `/api/v1`, All
Thing) directly as that device — no session token — under the **`Device`**
authorization scheme:

```
Authorization: Device <cert>~<proof>
```

- `<cert>` is the enrolment cert token the device persisted from pairing/enrolment.
- `<proof>` is a **possession proof**: the device signs, with its hardware-sealed
  key, `{"v":2,"typ":"void-which-binds.possession","crt":base64url(sha256(cert)),"iat":…,"exp":…}` (compact JSON, that
  order; the body IS the signed message) and renders it `base64url(body).base64url(sig)`.
  A cert says a user vouches for a device key; the proof shows the caller *holds*
  that key, bound to this very cert. It is stateless and short-lived — **120 s** by
  default — and the server honours it with **+30 s not-yet-valid tolerance and
  strict expiry** (void-which-binds-go `PossessionTTL` / `PossessionSkew`).
- `~` is the enrolment separator (outside the base64url alphabet, so unambiguous).

`auth/` is the one implementation every relying-party app shares — a byte-exact port
of void-which-binds-go v0.5.0 `enrolment.SignPossession`/`VerifyPossession`, pinned by Go-minted
golden vectors (`src/jvmTest/resources/vectors/`):

```kotlin
import one.rarebit.voidwhichbinds.auth.*

// The signer is the sealed device key — the same DeviceKeyStore seam the flows use.
val credential = DeviceCredential(
    certToken = persistedCertToken,
    signer = DeviceKeyStore.getOrCreate("device").asSigner(),
    clock = { System.currentTimeMillis() / 1000 },   // unix seconds
    // ttlSeconds = 120, reuseForSeconds = 90 (ttl − skew) are the defaults
)

// Any HTTP stack: stamp the header, and re-mint + retry ONCE on a 401.
val response = DeviceAuthPolicy.execute(credential, statusOf = { it.status }) { header ->
    transport.get(url, headers = mapOf(DeviceCredential.HEADER to header))
}
```

- **`credential.headerValue()`** returns the live `Device …` value, reusing one proof
  for `reuseForSeconds` (so a biometric-gated key is not prompted per request) and
  minting a fresh one once the window lapses; **`credential.refresh()`** forces a fresh
  proof (after a `401`, or on wake).
- **`DeviceAuthPolicy`** is transport-agnostic (no OkHttp, no coroutine runtime):
  `next(status, attempt)` is the pure decision, `execute` the generic `inline` driver
  (its `send` lambda may block or suspend). A relying party answers every refusal with
  the same `401`, so "re-mint once, then surface it" is the whole strategy.
- **Pure pieces** for tests and servers: `PossessionProof.mint/verify/parse/certHash`,
  `DeviceCredential.format/parse/headerValue/mint`.

## Build

Requires **JDK 21**. Uses the Gradle wrapper (self-downloads Gradle 8.9 +
Kotlin 2.3.20). The Android target needs an Android SDK (`ANDROID_HOME` /
`local.properties`); the iOS targets need the Kotlin/Native toolchain (auto-downloaded on macOS; Apple targets are skipped on Linux).

```sh
./gradlew jvmTest                          # compile + run common + JVM tests
./gradlew compileReleaseKotlinAndroid      # Android compile
./gradlew compileKotlinIosArm64            # iOS device compile (Kotlin/Native)
./gradlew iosSimulatorArm64Test            # commonTest on the iOS simulator (macOS)
./gradlew assembleVoidWhichBindsXCFramework      # → build/XCFrameworks/{debug,release}/VoidWhichBinds.xcframework
```

### The iOS `VoidWhichBinds.xcframework`

The SwiftUI app links the library as a single **XCFramework** named `VoidWhichBinds`
(device `ios-arm64` + `ios-arm64-simulator` slices). Build it with
`./gradlew assembleVoidWhichBindsReleaseXCFramework`, drag `VoidWhichBinds.xcframework` into
the Xcode app target (Embed & Sign), then `import VoidWhichBinds` — every type here is
exported (`UserIdentity`, `DeviceIdentity`, `Enrolment`, `LoginQr`/`VoidbindQr`,
`LoginApproval`/`DevicePairing`/`DeviceAuthorization`, `SecureEnclaveSealer`,
`VoidbindIos`). The app implements the `SecureEnclaveSealer` protocol in Swift
(CryptoKit/Security) and injects it once via `VoidbindIos.shared.doInit(sealer:)`.

## Targets

| Target | State |
|---|---|
| `jvm()` | dev/test — buildable **and** testable (software keystore) |
| `androidTarget()` | StrongBox/TEE-sealed Ed25519 seed; builds on the Android SDK |
| `iosArm64()`, `iosSimulatorArm64()` | compile + export the `VoidWhichBinds.xcframework`; the Secure Enclave `actual` needs the app-provided Swift `SecureEnclaveSealer` |

## Layout

See [`docs/agents/layout.md`](docs/agents/layout.md) for the full source map and [`AGENTS.md`](AGENTS.md) for the wire-contract rules.

## Releases — signed APKs, published per tag

Debug builds are a dead end: they are signed with the throwaway debug key, so they can
never be updated in place by a real release. Every tagged version is therefore built as
a **signed release APK** and attached to a GitHub Release, which is the artefact the
phone installs.

### Cutting a release

```sh
git tag app-v0.7.2          # `app-v<major>.<minor>.<patch>` — **the `app-v` prefix is load-bearing**: the shared `void-which-binds-client` library publishes on plain `v*` tags (`publish.yml`), so the app carries its own prefix and the two triggers never collide
git push origin app-v0.7.2
```

`.github/workflows/release.yml` picks the tag up, builds `:androidApp:assembleRelease`, verifies the
APK with `apksigner verify --print-certs`, and publishes the Release with
`cruciform-0.7.2.apk` attached. `versionName` comes from the tag; `versionCode` is derived from it
(`major*10000 + minor*100 + patch`), so neither is ever hand-edited.

The release job first checks the **endpoint defaults** it bakes into `BuildConfig`, read from
repository variables (none are committed). `CRUCIFORM_DEFAULT_RELAY` and `CRUCIFORM_MEMBERSHIP_RPS`
(comma-separated) are required, and the job fails before building if either is unset.
`CRUCIFORM_DEFAULT_NOTIFY` is optional: when it is unset the job only warns, and the build skips
push registration. Every value must be `https://`. Set them with
`gh variable set CRUCIFORM_DEFAULT_RELAY -R rarebit-one/void-which-binds-kmp --body 'https://…'`.

A release build also **forces the hardware-backed device engine** (`USE_DEVICE_ENGINE = true` in the `release` build type, plus `-PdeviceEngine=true` in CI) — the `PreviewVoidbindEngine` is a debug/CI affordance and must never ship in a signed release.

### Signing

`signingConfigs.release` reads four values, from the environment first and gradle
properties second — nothing is committed, and `*.jks` is git-ignored:

| Env | Gradle property | What |
|-----|-----------------|------|
| `RELEASE_KEYSTORE_BASE64` | `release.keystoreBase64` | the keystore, base64 |
| `RELEASE_KEYSTORE_PASSWORD` | `release.keystorePassword` | store password |
| `RELEASE_KEY_ALIAS` | `release.keyAlias` | `one.rarebit.cruciform` |
| `RELEASE_KEY_PASSWORD` | `release.keyPassword` | key password |

With none of them set the release build type is simply **unsigned** — a local
`assembleRelease` still works. CI supplies them from the repo secrets of the same
names. The keystore itself (RSA 4096, 25 years) lives at
`~/.config/rarebit-android-signing/cruciform.jks` and in **1Password → Sysadmins**.
Losing it means no user can ever update in place again.

Build a signed APK locally:

```sh
export RELEASE_KEYSTORE_BASE64=$(base64 -i ~/.config/rarebit-android-signing/cruciform.jks | tr -d '\n')
export RELEASE_KEYSTORE_PASSWORD=$(cat ~/.config/rarebit-android-signing/cruciform.password)
export RELEASE_KEY_PASSWORD="$RELEASE_KEYSTORE_PASSWORD"
export RELEASE_KEY_ALIAS=one.rarebit.cruciform
./gradlew :androidApp:assembleRelease -PreleaseVersionName=app-v0.7.2
```

### Getting it onto a phone

Download the APK from the Release and `adb install` it, or open the Release page on
the phone. There is deliberately no third-party app-store client in the loop.

How this is *meant* to be distributed — a self-hosted install page plus an in-app
updater that checks for and applies a new signed build — is being designed in
[`rarebit-one/heyarr-core#441`](https://github.com/rarebit-one/heyarr-core/issues/441).
Not built yet; this section is the pointer, not the plan.

