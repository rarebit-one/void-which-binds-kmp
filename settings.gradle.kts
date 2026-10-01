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
