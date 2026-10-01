# Build and test details

Moved verbatim from the old `CLAUDE.md` ("Build & test"). The commands themselves are in [`AGENTS.md`](../../AGENTS.md).

Host toolchain: **JDK 21** (bytecode targets JVM 17), no system `gradle`/`kotlin` —
use the **wrapper** (`./gradlew`, self-downloads Gradle 8.9; the Kotlin plugin is
**2.3.20**, required by cryptography-kotlin 0.6.0's metadata; AGP 8.7.3). All
plugin and dependency versions live in `gradle/libs.versions.toml` (the `libs`
catalog), shared by the root library and `:androidApp`. The
Android target and the `:androidApp` module need an Android SDK (`ANDROID_HOME` or
`local.properties`). The iOS targets compile only on **macOS** (Kotlin/Native Apple
targets are skipped on a Linux host).

Targets: `jvm()` (dev/test, software keystore), `androidTarget()` (StrongBox/TEE),
`iosArm64()` + `iosSimulatorArm64()` (Secure Enclave via the Swift sealer, exported
as the `VoidWhichBinds` XCFramework). Tests in `commonTest` run on every target; `jvmTest`
adds the golden-vector parity suites, the JVM keystore test and live-voidbind-go
interop (skipped when `go`/the void-which-binds-go checkout is absent). CI (`test.yml`) runs
`jvmTest` + the Android compile, ktlint + detekt, the app build + unit tests, and
the iOS compile + simulator tests on macOS. Lint findings that predate the linters
are frozen in each project's `config/ktlint/baseline.xml` / `config/detekt/baseline.xml`
(style: `.editorconfig`); fix new findings rather than regenerating the baselines.
The commonTest cases pinned to Go signature vectors
compare bytes only where Ed25519 signing is deterministic (JDK, JVM/Android).
CryptoKit signs with randomized Ed25519, so on iOS they check that the payload is
byte-identical and that both our signature and Go's verify (`ed25519SigningIsDeterministic`,
`assertMatchesGoToken` in commonTest).
