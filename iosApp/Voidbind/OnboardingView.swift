import SwiftUI
import VoidWhichBinds

/// Drives onboarding against the ``VoidbindEngine``: create a new identity, restore
/// from a written-down secret, or add this device to an existing account (pairing).
/// Coordinator/identity calls run OFF the main thread (the KMP transport + Secure
/// Enclave are blocking); results publish back on the main actor.
@MainActor
final class OnboardingViewModel: ObservableObject {

    enum Phase: Equatable {
        case choosing
        case backUpSecret(secret: String, userId: String, cert: String)
        case restoring
        case failed(String)
    }

    @Published var phase: Phase = .choosing
    @Published var busy = false
    @Published var secretInput = ""

    private let engine: VoidbindEngine
    /// Set by the host once the model exists (see ``OnboardingHost``).
    var onEnrolled: (_ userId: String, _ cert: String) -> Void = { _, _ in }

    init(engine: VoidbindEngine) {
        self.engine = engine
    }

    /// Mint a new identity + self-enrol this device, then surface the recovery
    /// secret to back up once before landing on Home.
    func createIdentity() {
        busy = true
        Task.detached(priority: .userInitiated) {
            let identity = self.engine.createIdentity()
            let device = self.engine.deviceIdentity()             // provisions the SE key (biometric)
            let cert = self.engine.enrolFirstDevice(identity: identity, device: device)
            let secret = identity.recovery.format()
            let userId = identity.userId.render()
            await MainActor.run {
                self.busy = false
                self.phase = .backUpSecret(secret: secret, userId: userId, cert: cert)
            }
        }
    }

    /// Restore an identity from the recovery secret, self-enrol this device, and go
    /// straight to Home (the secret is already backed up, by definition).
    func restoreIdentity() {
        let secret = secretInput
        busy = true
        Task.detached(priority: .userInitiated) {
            do {
                let identity = try self.engine.restoreIdentity(secret)
                let device = self.engine.deviceIdentity()
                let cert = self.engine.enrolFirstDevice(identity: identity, device: device)
                let userId = identity.userId.render()
                await MainActor.run {
                    self.busy = false
                    self.onEnrolled(userId, cert)
                }
            } catch {
                await MainActor.run {
                    self.busy = false
                    self.phase = .failed("That recovery secret didn’t check out — re-read it and try again.")
                }
            }
        }
    }
}

/// The onboarding screen set (create / restore / add-device), dark-first + teal.
struct OnboardingView: View {
    @ObservedObject var model: OnboardingViewModel
    /// Non-nil in the live app (to scan a pairing invite); nil in previews.
    var engine: VoidbindEngine? = nil
    @State private var showAddDevice = false

    var body: some View {
        Group {
            switch model.phase {
            case .choosing: chooser
            case .restoring: restore
            case .backUpSecret(let secret, let userId, let cert):
                RecoveryBackupView(secret: secret, userId: userId) {
                    model.onEnrolled(userId, cert)
                }
            case .failed(let message): failure(message)
            }
        }
        .vbScreen()
        .sheet(isPresented: $showAddDevice) {
            // Adding this device to an existing account = scan the existing
            // device's invite QR, which dispatches into the pairing (join) flow.
            if let engine {
                NavigationStack { ScanView(engine: engine) }
            }
        }
    }

    // MARK: - Chooser (the primary onboarding screen)

    private var chooser: some View {
        VStack(spacing: 0) {
            Spacer()
            VStack(spacing: 14) {
                ZStack {
                    Circle().fill(VB.teal.opacity(0.14)).frame(width: 92, height: 92)
                    Image(systemName: "key.horizontal.fill")
                        .font(.system(size: 38, weight: .semibold))
                        .foregroundStyle(VB.teal)
                }
                Text("Cruciform").font(VB.rounded(34, .bold))
                Text("Voidbind protocol").font(VB.rounded(12)).foregroundStyle(VB.textFaint)
                Text("Your identity is a key you hold — no account, no password, no server.")
                    .font(VB.rounded(15))
                    .foregroundStyle(VB.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            Spacer()
            VStack(spacing: 12) {
                Button { model.createIdentity() } label: {
                    Label("Create a new identity", systemImage: "sparkles")
                }
                .buttonStyle(VBPrimaryButtonStyle())

                Button { model.phase = .restoring } label: {
                    Label("Restore from recovery secret", systemImage: "arrow.clockwise")
                }
                .buttonStyle(VBSecondaryButtonStyle())

                Button { showAddDevice = true } label: {
                    Label("Add this device to an account", systemImage: "qrcode.viewfinder")
                }
                .buttonStyle(VBSecondaryButtonStyle())
            }
            .padding(.horizontal, 22)

            if model.busy { ProgressView().tint(VB.teal).padding(.top, 18) }
            Spacer().frame(height: 24)
        }
        .padding(.bottom, 8)
    }

    // MARK: - Restore

    private var restore: some View {
        VStack(alignment: .leading, spacing: 18) {
            backButton { model.phase = .choosing }
            Text("Restore your identity").font(VB.rounded(26, .bold))
            Text("Type the recovery secret you wrote down. It rebuilds the same identity, offline — a single wrong character is rejected, never guessed.")
                .font(VB.rounded(15)).foregroundStyle(VB.textSecondary)

            TextField("", text: $model.secretInput, prompt: Text("heyarr1…").foregroundColor(VB.textFaint))
                .font(VB.mono(15))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .padding(14)
                .background(VB.surface2, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(VB.hairline, lineWidth: 1))

            Button { model.restoreIdentity() } label: { Text("Restore") }
                .buttonStyle(VBPrimaryButtonStyle(enabled: !model.secretInput.isEmpty))
                .disabled(model.secretInput.isEmpty || model.busy)

            if model.busy { HStack { Spacer(); ProgressView().tint(VB.teal); Spacer() } }
            Spacer()
        }
        .padding(22)
    }

    private func failure(_ message: String) -> some View {
        VStack(spacing: 18) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40)).foregroundStyle(VB.danger)
            Text(message).font(VB.rounded(16)).foregroundStyle(VB.textSecondary)
                .multilineTextAlignment(.center).padding(.horizontal, 30)
            Button { model.phase = .restoring } label: { Text("Try again") }
                .buttonStyle(VBSecondaryButtonStyle()).padding(.horizontal, 40)
            Spacer()
        }
    }

    private func backButton(_ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: "chevron.left").font(.system(size: 17, weight: .semibold))
                .foregroundStyle(VB.textSecondary)
        }
    }
}
