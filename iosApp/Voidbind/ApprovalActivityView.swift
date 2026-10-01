import SwiftUI
import VoidWhichBinds

/// The **approval activity** log: the immutable "who did I approve, and when" trail —
/// one row per approve/deny decision, newest first. Read-only; the records are appended
/// by the login-approval flow as each sign-in is decided (commonMain `ApprovalAuditLog`).
struct ApprovalActivityView: View {
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss

    private var entries: [ApprovalAuditEntry] { model.approvalActivity(limit: 100) }

    var body: some View {
        ScrollView {
            if entries.isEmpty {
                emptyState
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(entries.enumerated()), id: \.offset) { _, entry in
                        row(entry)
                        if entry.loginId != entries.last?.loginId { Divider().overlay(VB.hairline) }
                    }
                }
                .vbCard(padding: 4)
                .padding(18)
                Text("This log stays on your device. It records what you approved or denied — never any personal data.")
                    .font(VB.rounded(12)).foregroundStyle(VB.textFaint)
                    .multilineTextAlignment(.center).padding(.horizontal, 24)
            }
        }
        .vbScreen()
        .navigationTitle("Approval activity")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Done") { dismiss() }.foregroundStyle(VB.teal)
            }
        }
        .toolbarBackground(VB.bg, for: .navigationBar)
    }

    private func row(_ entry: ApprovalAuditEntry) -> some View {
        let approved = entry.decision == ApprovalDecision.approved
        return HStack(spacing: 14) {
            Image(systemName: approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(approved ? VB.good : VB.danger).frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.rp).font(VB.rounded(15, .medium)).foregroundStyle(VB.textPrimary)
                Text(detail(entry, approved: approved))
                    .font(VB.rounded(12)).foregroundStyle(VB.textSecondary)
            }
            Spacer()
        }
        .padding(.vertical, 12).padding(.horizontal, 12)
    }

    private func detail(_ entry: ApprovalAuditEntry, approved: Bool) -> String {
        var parts = [approved ? "Approved" : "Denied", relativeTime(entry.timestampSeconds)]
        if let n = entry.matchNumber { parts.append("#\(n.intValue)") }
        return parts.joined(separator: " · ")
    }

    private func relativeTime(_ seconds: Int64) -> String {
        let date = Date(timeIntervalSince1970: Double(seconds))
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: date, relativeTo: Date())
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "clock.arrow.circlepath").font(.system(size: 40)).foregroundStyle(VB.textFaint)
            Text("No approvals yet").font(VB.rounded(17, .medium)).foregroundStyle(VB.textSecondary)
            Text("Each sign-in you approve or deny will appear here.")
                .font(VB.rounded(13)).foregroundStyle(VB.textFaint).multilineTextAlignment(.center)
        }
        .padding(.top, 80).padding(.horizontal, 24)
    }
}
