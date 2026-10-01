import SwiftUI
import VoidWhichBinds

/// The SwiftUI app entry. Builds the ``AppModel`` once (which builds the
/// ``VoidbindEngine``, injecting the Swift Secure Enclave sealer into the KMP
/// library) and shows ``RootView`` — onboarding until this device is enrolled,
/// then the Home dashboard.
///
/// In DEBUG builds a `VOID_WHICH_BINDS_PREVIEW_SCREEN` environment variable renders a
/// single screen with sample data (see ``PreviewHarness``), so each screen can be
/// screenshotted headless in the Simulator without a device, camera, or network.
///
/// > Builds + runs in the iOS Simulator via the XcodeGen project (see
/// > iosApp/README.md). The biometric/Secure-Enclave paths still need a real
/// > device (docs/DEVICE-TESTING.md).
@main
struct Cruciform: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            #if DEBUG
            if let screen = ProcessInfo.processInfo.environment["VOID_WHICH_BINDS_PREVIEW_SCREEN"] {
                PreviewHarness.view(for: screen)
            } else {
                RootView(model: model)
            }
            #else
            RootView(model: model)
            #endif
        }
    }
}
