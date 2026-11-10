plugins {
    // Declared `apply false` in the root build (one shared plugin classpath);
    // versions live in gradle/libs.versions.toml.
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.compose.multiplatform)
    // Exports the dependency licences; thirdPartyNotices renders them for the app image.
    alias(libs.plugins.aboutlibraries)
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

// Third-party notices for the desktop app image and release tarball. AboutLibraries
// exports the runtime classpath's libraries and licences (with full texts for the
// common ones) as JSON; thirdPartyNotices renders that as plain text, which
// Compose's appResourcesRootDir copies into the app image (lib/app/resources/) and
// desktopReleaseTarball also puts at the top of the tarball.
aboutLibraries {
    collect {
        // Only what ships: runtimeClasspath is what the app image packages. Without the
        // filter the export also reads Compose hot-reload's test classpath (JUnit, EPL-2.0).
        filterVariants.add("runtimeClasspath")
        // Licence texts the POMs only link (Bouncy Castle's MIT-style licence).
        configPath = file("aboutlibraries")
    }
    export {
        outputFile = layout.buildDirectory.file("generated/aboutLibraries/aboutlibraries.json").get().asFile
        prettyPrint = true
    }
}

val noticesRoot = layout.buildDirectory.dir("generated/notices")

val thirdPartyNotices by tasks.registering {
    group = "distribution"
    description = "Renders the AboutLibraries export as THIRD_PARTY_LICENSES.txt for the app image."
    dependsOn("exportLibraryDefinitions")
    val json = layout.buildDirectory.file("generated/aboutLibraries/aboutlibraries.json")
    val out = noticesRoot.map { it.file("common/THIRD_PARTY_LICENSES.txt") }
    inputs.file(json)
    outputs.file(out)
    doLast {
        @Suppress("UNCHECKED_CAST")
        val root = groovy.json.JsonSlurper().parse(json.get().asFile) as Map<String, Any?>
        val licences = (root["licenses"] as? Map<String, Map<String, Any?>>).orEmpty()
        val libraries = (root["libraries"] as? List<Map<String, Any?>>).orEmpty()
            .sortedBy { (it["name"] as? String ?: it["uniqueId"] as String).lowercase() }
        val used = linkedSetOf<String>()
        val text = buildString {
            appendLine("Third-party software in Cruciform for desktop")
            appendLine()
            appendLine("This app is built with the libraries below. Each lists its version and licence;")
            appendLine("the licence texts follow the list.")
            appendLine()
            for (lib in libraries) {
                val ids = (lib["licenses"] as? List<String>).orEmpty()
                used += ids
                val names = ids.joinToString { licences[it]?.get("name") as? String ?: it }
                val name = lib["name"] ?: lib["uniqueId"]
                appendLine("$name ${lib["artifactVersion"] ?: ""} (${lib["uniqueId"]}): $names")
            }
            for (id in used) {
                val def = licences[id] ?: continue
                appendLine()
                appendLine("=".repeat(78))
                appendLine("${def["name"] ?: id}${def["url"]?.let { " <$it>" } ?: ""}")
                appendLine("=".repeat(78))
                appendLine((def["content"] as? String)?.trim() ?: "See ${def["url"] ?: "the licence URL above"}.")
            }
        }
        out.get().asFile.apply { parentFile.mkdirs() }.writeText(text)
    }
}

compose.desktop.application.nativeDistributions.appResourcesRootDir.set(noticesRoot)
tasks.matching { it.name == "prepareAppResources" }.configureEach { dependsOn(thirdPartyNotices) }

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
        from(thirdPartyNotices)
    }
}

tasks.test {
    useJUnitPlatform()
    // One real unlock runs Argon2id at the floor (256 MiB).
    maxHeapSize = "1g"
}
