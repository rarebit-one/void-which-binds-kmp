import java.util.Base64
import java.util.Properties

plugins {
    // Declared `apply false` in the root build (one shared plugin classpath);
    // versions live in gradle/libs.versions.toml.
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.compose.compiler)
}

// ── Release version + signing ────────────────────────────────────────────────
// `versionName` comes from the git tag: CI passes `-PreleaseVersionName=$GITHUB_REF_NAME`
// (the tag, e.g. `app-v0.7.2`); a plain local build falls back to the constant below.
// `versionCode` is DERIVED from it (major*10000 + minor*100 + patch) so it is
// monotonic with the tag and never has to be hand-bumped.
// 1.0.0 is the first gen2-only (void-which-binds) build — void-which-binds-go ADR-0022: a
// new identity on install, the `void-which-binds:` scheme only, no gen1 state reader. Gen1
// Cruciform is 0.x (last app-v0.11.2, versionCode 1102), so every gen2 code is above it.
// Gen2 is kept off F-Droid until C2 (ADR-0022 C1) so gen1 phones do not auto-update: stage it
// with a prerelease tag (app-v1.0.0-rc.N), which release.yml publishes as a GitHub prerelease
// that the F-Droid puller skips; tag app-v1.0.0 at C2. versionCodeOf ignores the -rc suffix.
val releaseVersionName: String =
    providers.gradleProperty("releaseVersionName").orNull
        ?.trim()?.removePrefix("app-v")?.takeIf { it.isNotEmpty() }
        ?: "1.0.0"

fun versionCodeOf(name: String): Int {
    val parts = name.substringBefore('-').split('.').map { it.toIntOrNull() ?: 0 }
    return parts.getOrElse(0) { 0 } * 10_000 + parts.getOrElse(1) { 0 } * 100 + parts.getOrElse(2) { 0 }
}

// Signing material is read from the environment (CI: repo secrets) or gradle
// properties (locally: ~/.gradle/gradle.properties). NOTHING is ever committed —
// `*.jks` is git-ignored and the keystore is materialised into build/ from base64.
// The keys live at ~/.config/rarebit-android-signing/ and in 1Password (Sysadmins).
fun releaseSecret(env: String, property: String): String? = System.getenv(env)?.takeIf { it.isNotBlank() }
    ?: providers.gradleProperty(property).orNull?.takeIf { it.isNotBlank() }

val releaseKeystoreBase64 = releaseSecret("RELEASE_KEYSTORE_BASE64", "release.keystoreBase64")
val releaseKeystorePassword = releaseSecret("RELEASE_KEYSTORE_PASSWORD", "release.keystorePassword")
val releaseKeyAlias = releaseSecret("RELEASE_KEY_ALIAS", "release.keyAlias")
val releaseKeyPassword = releaseSecret("RELEASE_KEY_PASSWORD", "release.keyPassword")

// Present only when the base64 keystore was supplied; otherwise the release build
// type stays unsigned (a local `assembleRelease` still works, it just isn't signed).
val releaseKeystore: File? = releaseKeystoreBase64?.let { encoded ->
    layout.buildDirectory.file("release-signing/release.jks").get().asFile.apply {
        parentFile.mkdirs()
        writeBytes(Base64.getMimeDecoder().decode(encoded))
    }
}

// ── Endpoint defaults (BuildConfig) ──────────────────────────────────────────
// The pairing relay, push/wake plane and membership-push RPs a fresh install uses
// before the user sets anything in Settings. NONE are committed: a private LAN
// endpoint must never ship baked into the APK. Each is read from the environment
// (CI: repo variables) or a gradle property (`-P…`, ~/.gradle/gradle.properties, or
// this repo's git-ignored local.properties); unset means "not configured" and the
// app says so (Settings shows no default; "Add a device" asks for a relay; push
// registration is skipped). A debug build may take its own local-dev values via the
// `cruciformDebug*` properties, falling back to the shared ones.
//   CRUCIFORM_DEFAULT_RELAY   / cruciformDefaultRelay    / cruciformDebugDefaultRelay
//   CRUCIFORM_DEFAULT_NOTIFY  / cruciformDefaultNotify   / cruciformDebugDefaultNotify
//   CRUCIFORM_MEMBERSHIP_RPS  / cruciformMembershipRps   / cruciformDebugMembershipRps  (comma-separated)
val localProperties = Properties().apply {
    rootProject.file("local.properties").takeIf { it.isFile }?.inputStream()?.use { load(it) }
}

fun endpointSetting(env: String?, property: String): String? =
    env?.let { System.getenv(it) }?.takeIf { it.isNotBlank() }
        ?: providers.gradleProperty(property).orNull?.takeIf { it.isNotBlank() }
        ?: localProperties.getProperty(property)?.takeIf { it.isNotBlank() }

data class Endpoints(val relay: String, val notify: String, val membershipRps: String)

val releaseEndpoints = Endpoints(
    relay = endpointSetting("CRUCIFORM_DEFAULT_RELAY", "cruciformDefaultRelay").orEmpty().trim(),
    notify = endpointSetting("CRUCIFORM_DEFAULT_NOTIFY", "cruciformDefaultNotify").orEmpty().trim(),
    membershipRps = endpointSetting("CRUCIFORM_MEMBERSHIP_RPS", "cruciformMembershipRps").orEmpty().trim(),
)
val debugEndpoints = Endpoints(
    relay = endpointSetting(null, "cruciformDebugDefaultRelay")?.trim() ?: releaseEndpoints.relay,
    notify = endpointSetting(null, "cruciformDebugDefaultNotify")?.trim() ?: releaseEndpoints.notify,
    membershipRps = endpointSetting(null, "cruciformDebugMembershipRps")?.trim() ?: releaseEndpoints.membershipRps,
)

// A release blocks cleartext entirely (res/xml/network_security_config.xml), so an
// http:// default there could never connect: refuse it when a release is BUILT (not
// at configuration, so a shared http value used for local debug builds still works).
val releaseEndpointUrls: List<String> = listOf(releaseEndpoints.relay, releaseEndpoints.notify)
    .plus(releaseEndpoints.membershipRps.split(',').map { it.trim() })
    .filter { it.isNotEmpty() }
tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    doFirst {
        releaseEndpointUrls.forEach { url ->
            require(url.startsWith("https://")) { "Release endpoint defaults must be https:// (got \"$url\")." }
        }
    }
}

fun com.android.build.api.dsl.VariantDimension.endpointFields(e: Endpoints) {
    fun quoted(v: String) = "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    buildConfigField("String", "DEFAULT_RELAY_URL", quoted(e.relay))
    buildConfigField("String", "DEFAULT_NOTIFY_URL", quoted(e.notify))
    buildConfigField("String", "DEFAULT_MEMBERSHIP_RPS", quoted(e.membershipRps))
}

android {
    namespace = "one.rarebit.cruciform"
    compileSdk = 35

    defaultConfig {
        applicationId = "one.rarebit.cruciform"
        // minSdk 33 mirrors the library: StrongBox (API 28+) plus the modern
        // BiometricPrompt/CryptoObject API and a provider that carries Ed25519.
        minSdk = 33
        targetSdk = 35
        versionCode = versionCodeOf(releaseVersionName)
        versionName = releaseVersionName

        // Engine selection at BUILD time, no source edit: `-PdeviceEngine=true` (or
        // `deviceEngine=true` in gradle.properties) selects the real hardware-backed
        // DeviceVoidbindEngine; the default (false) keeps the PreviewVoidbindEngine so
        // CI and UI review never depend on a StrongBox/TEE device.
        val deviceEngine = providers.gradleProperty("deviceEngine").map { it.toBoolean() }.getOrElse(false)
        buildConfigField("boolean", "USE_DEVICE_ENGINE", deviceEngine.toString())
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        create("release") {
            // Left unconfigured (and unreferenced) when no keystore was supplied.
            releaseKeystore?.let { keystore ->
                storeFile = keystore
                storePassword = releaseKeystorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            endpointFields(debugEndpoints)
        }
        release {
            endpointFields(releaseEndpoints)
            // minify stays OFF until proguard rules exist for the reflective bits.
            isMinifyEnabled = false
            signingConfig = releaseKeystore?.let { signingConfigs.getByName("release") }
            // A RELEASE build is the real authenticator: force the hardware-backed
            // DeviceVoidbindEngine regardless of `-PdeviceEngine`. The preview engine
            // is a debug/CI affordance and must never ship in a signed release.
            buildConfigField("boolean", "USE_DEVICE_ENGINE", "true")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // The shared KMP library at the repo root: wire contract + hardware DeviceKeyStore.
    implementation(project(":"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    // SavedStateHandle for the per-flow ViewModels (in-progress flow state survives process death).
    implementation(libs.androidx.lifecycle.viewmodel.savedstate)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.biometric)
    // A modern fragment so FragmentActivity (needed by BiometricPrompt) extends the
    // androidx.activity.ComponentActivity that activity-compose's setContent requires
    // (biometric 1.1.0 alone pulls an older fragment).
    implementation(libs.androidx.fragment)

    // QR scanning: CameraX preview + analysis, ML Kit barcode decoding.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)
    // QR generation (invite codes this device displays) — ML Kit only decodes.
    implementation(libs.zxing.core)

    // The device engine's HttpTransport actual (relay + RP calls).
    implementation(libs.okhttp)

    // Pure-JVM unit tests (deep-link routing); no Android runtime needed.
    testImplementation(libs.junit)
    testImplementation(kotlin("test"))
    // The invite state machine (pairing/InviteCoordinator) is driven on a test dispatcher.
    testImplementation(libs.kotlinx.coroutines.test)
}

// RpPairManifestQueriesTest reads the manifest at runtime; make it a task input so an
// edit to <queries> re-runs the unit tests instead of hitting Gradle's up-to-date cache.
tasks.withType<Test>().configureEach {
    inputs.file(layout.projectDirectory.file("src/main/AndroidManifest.xml"))
        .withPropertyName("androidManifestForQueriesTest")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}
