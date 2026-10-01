import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    // Kotlin 2.3.x: cryptography-kotlin 0.6.0 (the release that adds Ed25519 +
    // X25519 across JDK/CryptoKit/OpenSSL) ships 2.3.x metadata, so the project
    // compiler must match. AGP bumped to a version compatible with Gradle 8.9.
    // Versions live in gradle/libs.versions.toml.
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.library)
    // :androidApp's plugins, declared here (not applied) so the whole build shares
    // one plugin classpath and :androidApp can apply them by alias.
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.compose.compiler) apply false
    // Publishes the shared client (identity/net/flow wire brain + DeviceKeyStore
    // seam) as the consumable `void-which-binds-client` artifact to GitHub Packages, so
    // relying-party apps (allthing-android, heyarr-mobile) depend on it over the
    // wire instead of re-implementing the login seam. See "Consuming as a
    // dependency" in README.md.
    id("maven-publish")
    // Lint (applied to every project below). Existing findings are frozen in
    // baselines, so only NEW violations fail CI.
    alias(libs.plugins.ktlint)
    alias(libs.plugins.detekt)
}

// ── Lint: ktlint + detekt, for the root library and :androidApp ─────────────────
// `./gradlew ktlintCheck detekt` is what CI runs. Findings that predate the linters
// live in each project's config/ktlint/baseline.xml and config/detekt/baseline.xml;
// fix code rather than growing them. Regenerate only to deliberately accept debt:
// `./gradlew ktlintGenerateBaseline detektBaseline`. Style is in .editorconfig.
allprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    apply(plugin = "io.gitlab.arturbosch.detekt")

    configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
        version.set(rootProject.libs.versions.ktlint)
        baseline.set(file("config/ktlint/baseline.xml"))
        filter {
            exclude { it.file.path.contains("/build/") }
        }
    }

    configure<io.gitlab.arturbosch.detekt.extensions.DetektExtension> {
        buildUponDefaultConfig = true
        // The KMP layout (src/commonMain, src/iosMain, …) is not in detekt's
        // default source set, so scan all of src/.
        source.setFrom("src")
        baseline = file("config/detekt/baseline.xml")
    }

    // detekt 1.23.8 embeds the Kotlin 2.0.21 compiler and refuses to run against a
    // newer one; keep its (isolated) tool classpath on the version it was built with.
    configurations.matching { it.name == "detekt" }.configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "org.jetbrains.kotlin") {
                useVersion(rootProject.libs.versions.detektKotlin.get())
            }
        }
    }
}

group = "one.rarebit.voidwhichbinds"
// Bump on any wire-affecting or API-affecting change; the coordinates are
// `one.rarebit.voidwhichbinds:void-which-binds-client`. 0.2.0 adds `VoidbindDeepLink` (the
// same-device app-to-app handoff URI, ADR-0003). 0.2.1 adds the non-throwing
// `*Catching` pairing steps + `PairingOutcome` (a relay you cannot reach is an
// error the UI renders, not a crash) and the typed `RelayHttpException`. 0.4.0 adds
// `auth/` — the Device-scheme possession proof (`PossessionProof`), the
// `Authorization: Device <cert>~<proof>` credential with its reuse window
// (`DeviceCredential`) and the transport-agnostic re-mint-and-retry-once policy
// (`DeviceAuthPolicy`), so every relying-party app shares ONE implementation.
// 0.5.0 adds the membership op-set (ADR-0005 / void-which-binds-go ADR-0007): `MembershipOp`
// (the v3 add/remove op, v1/v2 certs reinterpreted as genesis adds) and
// `Membership.evaluate`/`merge` (the CRDT evaluator, golden-vector parity with
// void-which-binds-go v0.9.0), so any member device can admit or remove another; invite v3
// carries `usr`, `PairflowInitiator`/`DeviceAuthorization` take a MEMBER device
// (`PairflowAuthority.Device`) or genesis, the responder evaluates the initiator's
// ops before deriving a SAS, `DevicePairing.confirm` returns the `Admission`
// {op, ops}, and `LoginApproval`/`WebLogin.Assertion` present `ops`.
// 0.6.0 generalises `DeviceKeyStore.getOrCreate` with a `userAuthValiditySeconds`
// param (default 30 s, so existing callers are unchanged): a caller can provision a
// second, distinct-alias wrapping key with a longer user-auth window (e.g.
// `"$base.authorising"`, 3600 s) so ONE biometric authorises an hour of short
// possession-proof signing while each minted proof stays short — the client-side fix
// for heyarr-core#444/#443 (server ceiling returns to 10 min once apps adopt it).
// Android maps it to `setUserAuthenticationParameters`; iOS to the LAContext reuse
// duration (platform-capped at 10 min); JVM ignores it (software).
// k0:keep-begin version
// 0.10.0 is void-which-binds-go ADR-0013 R1 (K0): a packaging-only rename, the wire
// byte-identical to 0.9.0. The coordinates become
// `one.rarebit.voidwhichbinds:void-which-binds-client` (0.9.0 and earlier stay at
// `one.rarebit.voidbind:voidbind-client`), the Kotlin package and Android namespace
// `one.rarebit.voidwhichbinds`, the XCFramework `VoidWhichBinds`, the repo
// `rarebit-one/void-which-binds-kmp`. Class names (`VoidbindDeepLink`, `VoidbindQr`,
// `VoidbindAndroid`, …), every typ/label/HRP/header, the `voidbind:` scheme, the
// RP_HANDOFF category and every keystore alias, pref and dir keep their gen1
// spelling until gen2 (0.11.0, void-which-binds-go ADR-0022).
// k0:keep-end
version = "0.10.0"

repositories {
    mavenCentral()
    google()
}

// cryptography-kotlin (whyoleg) supplies SOFTWARE Ed25519 + X25519 across every
// target — including Kotlin/Native (iOS), where there is no java.security. It
// delegates to vetted primitives per platform (JDK on JVM/Android, CryptoKit on
// Apple). The HARDWARE wrapping key that seals the Ed25519 seed stays platform
// native (AndroidKeyStore / Secure Enclave) and never touches this library.
// See docs/adr/0001-hardware-keystore-mechanism.md. (Version: gradle/libs.versions.toml.)

kotlin {
    // `expect`/`actual` classes are a Beta feature we lean on for DeviceKeyStore;
    // opt in to silence the (expected) stability warning.
    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    // JVM — dev/test target (software key; isHardwareBacked = false).
    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }

    // Android — StrongBox/TEE-backed AES-GCM seal over a software Ed25519 key.
    androidTarget {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
        // Publish only the release variant of the Android artifact
        // (`void-which-binds-client-android`) — deterministic, and what a consuming app
        // resolves. Debug is a build-time concern of the consuming app.
        publishLibraryVariants("release")
    }

    // iOS — Secure-Enclave-P256 ECIES seal over a software Ed25519 key. Building
    // the Native targets needs the Kotlin/Native toolchain (auto-downloaded); the
    // Secure Enclave `actual` uses the Security framework via the K/N platform libs.
    //
    // The iOS SwiftUI app links this as a single **XCFramework** named `VoidWhichBinds`
    // (device arm64 + simulator arm64 slices). `./gradlew assembleVoidWhichBindsXCFramework`
    // produces `build/XCFrameworks/{debug,release}/VoidWhichBinds.xcframework`; the Swift
    // app imports `VoidWhichBinds` and provides the `SecureEnclaveSealer` via
    // `VoidbindIos.init(...)`. Dynamic (default) is fine — the framework carries the
    // cryptography-kotlin/CryptoKit backend with it.
    val xcf = XCFramework("VoidWhichBinds")
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "VoidWhichBinds"
            xcf.add(this)
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.cryptography.core)
            // The "optimal" provider selects the best backend per target: the JDK
            // provider on JVM/Android, CryptoKit on Apple. One dependency, no
            // per-target wiring, and Ed25519/X25519 are supported on all of them
            // (cryptography-kotlin 0.6.0).
            implementation(libs.cryptography.provider.optimal)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

android {
    namespace = "one.rarebit.voidwhichbinds"
    compileSdk = 35
    defaultConfig {
        // minSdk 33: StrongBox (API 28+) plus a platform that reliably carries
        // Ed25519 in its provider and the modern BiometricPrompt/CryptoObject API.
        minSdk = 33
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// ── Publishing: `void-which-binds-client` on GitHub Packages ───────────────────────────
// The shared client — the pure `commonMain` identity/net/flow wire brain
// (UserIdentity, DeviceIdentity, Enrolment, RelayClient, WebLoginClient,
// NotifyClient, PairflowInitiator/Responder, VoidbindCertSealer, the
// LoginApproval/DevicePairing/DeviceAuthorization coordinators, LoginQr/WebLogin,
// challenge-v2 number-match) plus the `DeviceKeyStore` hardware seam — is this KMP
// module. The per-app hardware wiring (Android `VoidbindAndroid.init(context)` +
// BiometricPrompt, iOS `SecureEnclaveSealer` via `VoidbindIos`) stays in each
// consuming app; the published artifact is the shared wire/flow brain, not the app.
//
// The Kotlin Multiplatform plugin creates one publication per target; we only
// rename each artifactId from the project name (`void-which-binds-kmp`) to
// `void-which-binds-client`, giving:
//   one.rarebit.voidwhichbinds:void-which-binds-client                    (root Gradle-metadata)
//   one.rarebit.voidwhichbinds:void-which-binds-client-jvm
//   one.rarebit.voidwhichbinds:void-which-binds-client-android
//   one.rarebit.voidwhichbinds:void-which-binds-client-iosarm64
//   one.rarebit.voidwhichbinds:void-which-binds-client-iossimulatorarm64
// Consumers depend on the root coordinate and Gradle resolves the right variant.
publishing {
    publications.withType<MavenPublication>().configureEach {
        pom {
            name.set("void-which-binds-client")
            description.set(
                "Void-Which-Binds shared client — the Kotlin Multiplatform identity/net/flow " +
                    "wire brain (login/pairing/authorization) plus the DeviceKeyStore " +
                    "hardware seam. The consumable side of void-which-binds-kmp.",
            )
            url.set("https://github.com/rarebit-one/void-which-binds-kmp")
            licenses {
                license {
                    name.set("The Apache Software License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/rarebit-one/void-which-binds-kmp")
            credentials {
                // CI provides GITHUB_ACTOR/GITHUB_TOKEN; locally, GPR_USER/GPR_TOKEN
                // (a PAT with read:packages / write:packages) fall back in.
                username = System.getenv("GITHUB_ACTOR") ?: findProperty("gpr.user") as String?
                    ?: System.getenv("GPR_USER")
                password = System.getenv("GITHUB_TOKEN") ?: findProperty("gpr.token") as String?
                    ?: System.getenv("GPR_TOKEN")
            }
        }
    }
}

// Rename every publication's artifactId from the project name (`void-which-binds-kmp`) to
// `void-which-binds-client`. This runs in `afterEvaluate` because the Android Gradle
// Plugin sets the Android variant publication's artifactId in its OWN
// `afterEvaluate` (registered when the plugin is applied, i.e. earlier than this
// block) — so a plain `configureEach` rename is overwritten back to
// `void-which-binds-kmp-android`. Renaming here, after all plugin `afterEvaluate` hooks,
// makes every target — including `-android` — consistently `void-which-binds-client-*`,
// and keeps the root Gradle-module metadata's variant coordinates in sync.
afterEvaluate {
    publishing.publications.withType<MavenPublication>().configureEach {
        artifactId = artifactId.replace(rootProject.name, "void-which-binds-client")
    }
}
