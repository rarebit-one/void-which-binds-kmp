import Security
import SwiftUI
import VoidWhichBinds

enum PairMode { case connect, join }

/// The device-pairing flow, both sides:
///  - **connect** (existing device authorising a new one): opens a relay session,
///    shows the invite QR, runs the handshake, displays the 7-digit SAS, and — only
///    after the human confirms both screens match — signs + seals the cert.
///  - **join** (new device): scans the invite, runs the handshake, shows the SAS,
///    and on confirm receives + verifies the sealed cert.
///
/// The 7-digit SAS is the human gate that closes the relay-substitution / rushing
/// attack: enrolment only proceeds when both devices show the same number.
@MainActor
final class PairModel: ObservableObject {

    enum Phase: Equatable {
        case preparing
        case invite(qr: String)     // connect: render QR, waiting for the peer to join
        case verify(sas: String)    // both: compare the number
        case finishing
        case done
        case failed(String)
    }

    let mode: PairMode
    @Published var phase: Phase

    private let engine: VoidbindEngine?
    private let joinQr: String?
    private let authIdentity: UserIdentity?
    private let relayBase: String

    // Live state carried between steps.
    private var pairing: DevicePairing?
    private var handshake: DevicePairing.Handshake?
    private var authorization: DeviceAuthorization?
    private var invitation: DeviceAuthorization.Invitation?

    /// Live.
    init(mode: PairMode, engine: VoidbindEngine?, joinQr: String? = nil,
         authIdentity: UserIdentity? = nil,
         relayBase: String = "https://relay.voidbind.rarebit.one") {
        self.mode = mode; self.engine = engine; self.joinQr = joinQr
        self.authIdentity = authIdentity; self.relayBase = relayBase
        self.phase = .preparing
    }

    /// Sample (screenshots / previews).
    static func sample(_ phase: Phase, mode: PairMode) -> PairModel {
        let m = PairModel(mode: mode, engine: nil)
        m.phase = phase
        return m
    }

    /// Kick off the flow when the view appears (no-op in sample mode / missing inputs).
    func start() {
        guard case .preparing = phase, let engine else { return }
        switch mode {
        case .join:
            guard let joinQr else { return }
            Task.detached(priority: .userInitiated) {
                let pairing = engine.makeDevicePairing()
                do {
                    let hs = try pairing.begin(inviteQr: joinQr)
                    await MainActor.run {
                        self.pairing = pairing; self.handshake = hs; self.phase = .verify(sas: hs.sas)
                    }
                } catch {
                    await MainActor.run { self.phase = .failed("Couldn’t reach the other device. Try scanning again.") }
                }
            }
        case .connect:
            guard let authIdentity else { return } // authorising needs the user identity
            Task.detached(priority: .userInitiated) {
                let auth = engine.makeDeviceAuthorization(identity: authIdentity)
                do {
                    let invitation = try auth.invite(relayBase: self.relayBase, salt: Self.randomSalt())
                    await MainActor.run {
                        self.authorization = auth; self.invitation = invitation
                        self.phase = .invite(qr: invitation.inviteQr)
                    }
                    let sas = try auth.handshake(invitation: invitation)
                    await MainActor.run { self.phase = .verify(sas: sas) }
                } catch {
                    await MainActor.run { self.phase = .failed("Pairing didn’t complete.") }
                }
            }
        }
    }

    /// The human confirmed the numbers match: finish (authorise / receive the cert).
    func confirmMatch(onEnrolled: @escaping (_ cert: String) -> Void) {
        phase = .finishing
        // Read the live state on the main actor before hopping off it.
        let mode = self.mode
        let pairing = self.pairing, hs = self.handshake
        let auth = self.authorization, inv = self.invitation
        Task.detached(priority: .userInitiated) {
            do {
                switch mode {
                case .join:
                    guard let pairing, let hs else { await MainActor.run { self.phase = .done }; return }
                    let cert = try pairing.confirm(handshake: hs)
                    await MainActor.run { self.phase = .done; onEnrolled(cert) }
                case .connect:
                    guard let auth, let inv else { await MainActor.run { self.phase = .done }; return }
                    try auth.authorise(invitation: inv)
                    await MainActor.run { self.phase = .done }
                }
            } catch {
                await MainActor.run { self.phase = .failed("The pairing couldn’t be verified — don’t trust it.") }
            }
        }
    }

    private nonisolated static func randomSalt() -> KotlinByteArray {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).toKotlinByteArray()
    }
}

struct PairView: View {
    @StateObject private var model: PairModel
    @Environment(\.dismiss) private var dismiss
    var onEnrolled: (_ cert: String) -> Void

    /// Live.
    init(mode: PairMode, engine: VoidbindEngine?, joinQr: String? = nil,
         authIdentity: UserIdentity? = nil,
         onEnrolled: @escaping (String) -> Void = { _ in }) {
        _model = StateObject(wrappedValue: PairModel(mode: mode, engine: engine,
                                                     joinQr: joinQr, authIdentity: authIdentity))
        self.onEnrolled = onEnrolled
    }
    /// Sample.
    init(model: PairModel, onEnrolled: @escaping (String) -> Void = { _ in }) {
        _model = StateObject(wrappedValue: model)
        self.onEnrolled = onEnrolled
    }

    var body: some View {
        VStack(spacing: 20) {
            switch model.phase {
            case .preparing: preparing
            case .invite(let qr): invite(qr)
            case .verify(let sas): verify(sas)
            case .finishing: finishing
            case .done: done
            case .failed(let message): failure(message)
            }
        }
        .padding(22)
        .vbScreen()
        .navigationTitle(model.mode == .connect ? "Add a device" : "Join an account")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Close") { dismiss() }.foregroundStyle(VB.teal)
            }
        }
        .toolbarBackground(VB.bg, for: .navigationBar)
        .onAppear { model.start() }
    }

    private var preparing: some View {
        VStack(spacing: 14) { Spacer(); ProgressView().tint(VB.teal)
            Text(model.mode == .connect ? "Opening a pairing session…" : "Connecting…")
                .font(VB.rounded(14)).foregroundStyle(VB.textSecondary); Spacer() }
    }

    private func invite(_ qr: String) -> some View {
        VStack(spacing: 18) {
            Text("Scan this on the new device").font(VB.rounded(20, .bold))
                .multilineTextAlignment(.center)
            QRCodeView(payload: qr, size: 220)
            Text("Open Cruciform on your other device and choose “Add this device to an account.”")
                .font(VB.rounded(14)).foregroundStyle(VB.textSecondary)
                .multilineTextAlignment(.center).padding(.horizontal, 8)
            HStack(spacing: 8) { ProgressView().tint(VB.teal).controlSize(.small)
                Text("Waiting for the other device…").font(VB.rounded(13)).foregroundStyle(VB.textFaint) }
            Spacer()
        }
    }

    private func verify(_ sas: String) -> some View {
        VStack(spacing: 20) {
            Spacer()
            VStack(spacing: 8) {
                Image(systemName: "checkmark.shield.fill").font(.system(size: 34)).foregroundStyle(VB.teal)
                Text("Confirm the numbers match").font(VB.rounded(20, .bold))
                Text("Both devices should show the same 7 digits. If they differ, do not continue — someone may be in the middle.")
                    .font(VB.rounded(14)).foregroundStyle(VB.textSecondary)
                    .multilineTextAlignment(.center).padding(.horizontal, 6)
            }
            Text(spaced(sas))
                .font(VB.mono(40, .bold)).foregroundStyle(VB.teal)
                .padding(.vertical, 18).frame(maxWidth: .infinity)
                .background(VB.surface, in: RoundedRectangle(cornerRadius: 18))
                .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(VB.hairline, lineWidth: 1))
            Spacer()
            Button { model.confirmMatch(onEnrolled: onEnrolled) } label: {
                Text("They match")
            }.buttonStyle(VBPrimaryButtonStyle())
            Button { dismiss() } label: { Text("They’re different — stop") }
                .buttonStyle(VBSecondaryButtonStyle())
        }
    }

    private var finishing: some View {
        VStack(spacing: 14) { Spacer(); ProgressView().tint(VB.teal)
            Text("Finishing up…").font(VB.rounded(14)).foregroundStyle(VB.textSecondary); Spacer() }
    }

    private var done: some View {
        VStack(spacing: 16) { Spacer()
            Image(systemName: "checkmark.seal.fill").font(.system(size: 52)).foregroundStyle(VB.good)
            Text(model.mode == .connect ? "Device added" : "You’re in").font(VB.rounded(22, .bold))
            Text(model.mode == .connect
                 ? "The new device is now enrolled on your account."
                 : "This device is now enrolled and ready to use.")
                .font(VB.rounded(15)).foregroundStyle(VB.textSecondary)
                .multilineTextAlignment(.center).padding(.horizontal, 16)
            Spacer()
            Button { dismiss() } label: { Text("Done") }.buttonStyle(VBPrimaryButtonStyle())
        }
    }

    private func failure(_ message: String) -> some View {
        VStack(spacing: 16) { Spacer()
            Image(systemName: "xmark.octagon.fill").font(.system(size: 48)).foregroundStyle(VB.danger)
            Text("Pairing stopped").font(VB.rounded(20, .bold))
            Text(message).font(VB.rounded(15)).foregroundStyle(VB.textSecondary)
                .multilineTextAlignment(.center).padding(.horizontal, 16)
            Spacer()
            Button { dismiss() } label: { Text("Close") }.buttonStyle(VBSecondaryButtonStyle())
        }
    }

    /// Space the 7 digits as 3-4 for readability.
    private func spaced(_ sas: String) -> String {
        guard sas.count == 7 else { return sas }
        let i = sas.index(sas.startIndex, offsetBy: 3)
        return "\(sas[..<i]) \(sas[i...])"
    }
}
