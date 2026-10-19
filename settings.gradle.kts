rootProject.name = "void-which-binds-kmp"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}

// The first-party Android authenticator app. It is a separate application module
// that depends on the root KMP library (project(":")) — the shared wire contract
// and hardware DeviceKeyStore — and adds the Compose UI, CameraX, and biometrics.
// Additive: the library at the root is untouched.
include(":androidApp")

// The desktop authenticator (Compose Desktop, JVM): holds a passphrase-sealed device in
// void-which-binds-go's device directory (ADR-0010, #127). Depends on the root library.
include(":desktopApp")
