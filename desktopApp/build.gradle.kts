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

compose.desktop {
    application {
        mainClass = "one.rarebit.cruciform.desktop.MainKt"
        // No Deb/Rpm: they would not register the void-which-binds: scheme. The release
        // ships the app image with a .desktop entry and an installer that does (packaging).
        nativeDistributions {
            packageName = "cruciform-desktop"
            packageVersion = "1.0.0"
            // java.net.http (JdkHttpTransport) is not in jpackage's default module set.
            modules("java.net.http")
        }
    }
}

tasks.test {
    useJUnitPlatform()
    // One real unlock runs Argon2id at the floor (256 MiB).
    maxHeapSize = "1g"
}
