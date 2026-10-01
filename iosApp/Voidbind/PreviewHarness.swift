#if DEBUG
import SwiftUI
import VoidWhichBinds

/// Renders a single screen with representative sample data, selected by the
/// `VOID_WHICH_BINDS_PREVIEW_SCREEN` launch environment variable. This is a **DEBUG-only**
/// dev harness so each of the eight screens can be screenshotted headless in the
/// Simulator (no device, camera, Secure Enclave, or network) — it is not part of
/// the shipping app path (`RootView`).
///
/// Screenshot one screen:
/// ```sh
/// SIMCTL_CHILD_VOID_WHICH_BINDS_PREVIEW_SCREEN=home \
///   xcrun simctl launch --terminate-running-process <udid> one.rarebit.cruciform
/// xcrun simctl io <udid> screenshot home.png
/// ```
enum PreviewHarness {

    static let sampleUserId =
        "ed25519:3b6a4f2c9d8e1a0b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b"
    static let sampleSecret =
        "void-which-binds1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0stska6c"
    static let sampleSAS = "8591300"
    static let sampleInvite =
        "void-which-binds:pair?v=4&relay=https%3A%2F%2Frelay.example.test" +
        "&session=8f3a1c9d2b7e4056&salt=QmFydGxleVJpZGdlU2FsdDEyMzQ1Ng"

    @MainActor
    static func sampleModel() -> AppModel {
        let m = AppModel(engine: VoidbindEngine(), preview: true)
        m.enrolment = .enrolled(userId: sampleUserId, cert: "cert.sample")
        m.trustedSites = [
            TrustedSite(origin: "https://thesim.family", lastUsed: Date().addingTimeInterval(-3600)),
            TrustedSite(origin: "https://git.rarebit.one", lastUsed: Date().addingTimeInterval(-86400 * 2)),
        ]
        return m
    }

    @MainActor
    @ViewBuilder
    static func view(for screen: String) -> some View {
        switch screen {
        case "onboarding":
            OnboardingView(model: OnboardingViewModel(engine: VoidbindEngine()))
        case "recovery":
            RecoveryBackupView(secret: sampleSecret, userId: sampleUserId) {}
        case "home":
            HomeView(model: sampleModel())
        case "scan":
            NavigationStack { ScanView(engine: VoidbindEngine()) }
        case "login":
            NavigationStack {
                WebLoginApprovalView(
                    model: WebLoginModel(sampleRP: "https://thesim.family",
                                         audience: "https://thesim.family", expiresIn: 55))
            }
        case "pair-connect":
            NavigationStack { PairView(model: .sample(.invite(qr: sampleInvite), mode: .connect)) }
        case "pair-verify":
            NavigationStack { PairView(model: .sample(.verify(sas: sampleSAS), mode: .join)) }
        case "settings":
            NavigationStack { SettingsView(model: sampleModel()) }
        default:
            Text("Unknown preview screen: \(screen)").vbScreen()
        }
    }
}
#endif
