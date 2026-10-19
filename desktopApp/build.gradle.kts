plugins {
    // Declared `apply false` in the root build (one shared plugin classpath);
    // versions live in gradle/libs.versions.toml.
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose.multiplatform)
}

// Bytecode for JVM 17, built on the host JDK (21), as the root library is.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    // The root KMP library's JVM variant: the flows, plus custody/GoDeviceDir and
    // SealedDeviceKeys (ADR-0010).
    implementation(project(":"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(libs.kotlinx.coroutines.swing)
    implementation(libs.zxing.core)

    testImplementation(kotlin("test"))
}

// Compose-aware detekt rules on top of the shared defaults.
detekt {
    config.from(file("config/detekt/detekt.yml"))
}

// The root library's golden vectors, so the engine tests run against Go's device directory.
sourceSets.test {
    resources.srcDir(rootProject.file("src/jvmTest/resources"))
}

// The version comes from the release tag: CI passes `-PdesktopReleaseVersion=desktop-v1.2.3`
// (release-desktop.yml); a local build falls back to the constant. Not `releaseVersionName`:
// a -P property reaches every project, and :androidApp derives its versionCode from that one. jpackage takes only
// MAJOR.MINOR.PATCH, so a prerelease suffix (-rc.1) stays in the tarball's name only.
val desktopVersion: String =
    providers.gradleProperty("desktopReleaseVersion").orNull
        ?.trim()?.removePrefix("desktop-v")?.takeIf { it.isNotEmpty() }
        ?: "1.0.0"

compose.desktop {
    application {
        mainClass = "one.rarebit.cruciform.desktop.MainKt"
        // No Deb/Rpm: they would not register the void-which-binds: scheme. The release
        // ships the app image with a .desktop entry and an installer that does (packaging).
        nativeDistributions {
            packageName = "cruciform-desktop"
            packageVersion = desktopVersion.substringBefore('-')
            // java.net.http (JdkHttpTransport) is not in jpackage's default module set.
            modules("java.net.http")
        }
    }
}

// The release artefact: the self-contained app image (its own runtime) plus the .desktop
// entry and install.sh, which registers the void-which-binds: scheme for the user.
val desktopReleaseTarball by tasks.registering(Tar::class) {
    group = "distribution"
    description = "Packs the app image, its .desktop entry and install.sh for a release."
    dependsOn("createDistributable")
    val arch = System.getProperty("os.arch").let { if (it == "amd64") "x86_64" else it }
    archiveFileName.set("cruciform-desktop-$desktopVersion-linux-$arch.tar.gz")
    destinationDirectory.set(layout.buildDirectory.dir("release"))
    compression = Compression.GZIP
    into("cruciform-desktop-$desktopVersion") {
        from(layout.buildDirectory.dir("compose/binaries/main/app"))
        from("packaging/linux")
    }
}

tasks.test {
    useJUnitPlatform()
    // One real unlock runs Argon2id at the floor (256 MiB).
    maxHeapSize = "1g"
}
