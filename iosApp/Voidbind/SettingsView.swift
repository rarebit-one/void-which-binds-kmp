import SwiftUI
import VoidWhichBinds

/// Settings: the identity summary, adding another device, the security posture, and
/// signing this device out (which forgets the local enrolment but never destroys
/// the account — the recovery secret still restores it).
struct SettingsView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var showAddDevice = false
    @State private var showActivity = false
    @State private var confirmSignOut = false

    private var userId: String {
        if case let .enrolled(userId, _) = model.enrolment { return userId }
        return ""
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                identityCard
                section(title: "Devices") {
                    row(icon: "plus.rectangle.on.rectangle", title: "Add another device",
                        subtitle: "Authorise a new phone or tablet") { showAddDevice = true }
                }
                section(title: "Security") {
                    infoRow(icon: "cpu.fill", title: "Secure Enclave", value: "Sealed")
                    Divider().overlay(VB.hairline)
                    infoRow(icon: "faceid", title: "Biometric gate", value: "On")
                    Divider().overlay(VB.hairline)
                    infoRow(icon: "wifi.slash", title: "Verification", value: "Offline")
                }
                section(title: "Approvals") {
                    row(icon: "clock.arrow.circlepath", title: "Approval activity",
                        subtitle: "Who you approved, and when") { showActivity = true }
                }
                section(title: "Account") {
                    row(icon: "rectangle.portrait.and.arrow.right", title: "Sign out of this device",
                        subtitle: "Your recovery secret still restores the account",
                        tint: VB.danger) { confirmSignOut = true }
                }
                Text("Cruciform • Voidbind protocol\nNo account, no password, no server.")
                    .font(VB.rounded(12)).foregroundStyle(VB.textFaint)
                    .multilineTextAlignment(.center).padding(.top, 8)
            }
            .padding(18)
        }
        .vbScreen()
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }.foregroundStyle(VB.teal)
            }
        }
        .toolbarBackground(VB.bg, for: .navigationBar)
        .sheet(isPresented: $showAddDevice) {
            NavigationStack { AddDeviceGate(engine: model.engine) }
        }
        .sheet(isPresented: $showActivity) {
            NavigationStack { ApprovalActivityView(model: model) }
        }
        .confirmationDialog("Sign out of this device?", isPresented: $confirmSignOut, titleVisibility: .visible) {
            Button("Sign out", role: .destructive) { model.signOut(); dismiss() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This forgets the identity on this device. You can restore it with your recovery secret.")
        }
    }

    private var identityCard: some View {
        VStack(spacing: 10) {
            ZStack {
                Circle().fill(VB.teal.opacity(0.12)).frame(width: 60, height: 60)
                Image(systemName: "person.fill").font(.system(size: 26)).foregroundStyle(VB.teal)
            }
            Text("Your identity").font(VB.rounded(13)).foregroundStyle(VB.textFaint)
            Text(Fingerprint.short(userId)).font(VB.mono(16, .medium)).foregroundStyle(VB.teal)
        }
        .frame(maxWidth: .infinity).vbCard(padding: 20)
    }

    private func section<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title.uppercased()).font(VB.rounded(12, .semibold)).foregroundStyle(VB.textFaint)
                .padding(.leading, 4)
            VStack(spacing: 0) { content() }.vbCard(padding: 4)
        }
    }

    private func row(icon: String, title: String, subtitle: String,
                     tint: Color = VB.teal, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: icon).foregroundStyle(tint).frame(width: 26)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(VB.rounded(15, .medium)).foregroundStyle(VB.textPrimary)
                    Text(subtitle).font(VB.rounded(12)).foregroundStyle(VB.textFaint)
                }
                Spacer()
                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(VB.textFaint)
            }
            .padding(.vertical, 12).padding(.horizontal, 12)
        }
    }

    private func infoRow(icon: String, title: String, value: String) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon).foregroundStyle(VB.teal).frame(width: 26)
            Text(title).font(VB.rounded(15, .medium))
            Spacer()
            VBPill(text: value)
        }
        .padding(.vertical, 12).padding(.horizontal, 12)
    }
}

/// Authorising a new device requires proving you hold the account key, so the gate
/// asks for the recovery secret, restores the identity, then opens the CONNECT flow.
struct AddDeviceGate: View {
    let engine: VoidbindEngine
    @Environment(\.dismiss) private var dismiss
    @State private var secret = ""
    @State private var identity: UserIdentity?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Group {
            if let identity {
                PairView(mode: .connect, engine: engine, authIdentity: identity)
            } else {
                gate
            }
        }
    }

    private var gate: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Confirm it’s you").font(VB.rounded(24, .bold))
            Text("Adding a device signs a new key onto your account, so it needs your recovery secret.")
                .font(VB.rounded(15)).foregroundStyle(VB.textSecondary)
            TextField("", text: $secret, prompt: Text("heyarr1…").foregroundColor(VB.textFaint))
                .font(VB.mono(15)).autocorrectionDisabled().textInputAutocapitalization(.never)
                .padding(14).background(VB.surface2, in: RoundedRectangle(cornerRadius: 12))
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(VB.hairline, lineWidth: 1))
            if let error { Text(error).font(VB.rounded(13)).foregroundStyle(VB.danger) }
            Button { unlock() } label: { Text("Continue") }
                .buttonStyle(VBPrimaryButtonStyle(enabled: !secret.isEmpty && !busy))
                .disabled(secret.isEmpty || busy)
            if busy { HStack { Spacer(); ProgressView().tint(VB.teal); Spacer() } }
            Spacer()
        }
        .padding(22).vbScreen()
        .navigationTitle("Add a device").navigationBarTitleDisplayMode(.inline)
        .toolbar { ToolbarItem(placement: .cancellationAction) {
            Button("Close") { dismiss() }.foregroundStyle(VB.teal) } }
        .toolbarBackground(VB.bg, for: .navigationBar)
    }

    private func unlock() {
        busy = true; error = nil
        let s = secret
        Task.detached(priority: .userInitiated) {
            do {
                let id = try engine.restoreIdentity(s)
                await MainActor.run { self.identity = id; self.busy = false }
            } catch {
                await MainActor.run { self.error = "That recovery secret didn’t check out."; self.busy = false }
            }
        }
    }
}
