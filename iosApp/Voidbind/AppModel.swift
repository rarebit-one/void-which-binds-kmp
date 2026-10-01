import Foundation
import SwiftUI
import VoidWhichBinds

/// A relying party this identity has signed into, shown on Home.
struct TrustedSite: Identifiable, Hashable {
    let id = UUID()
    let origin: String        // e.g. "https://thesim.family"
    let lastUsed: Date
    var host: String { URL(string: origin)?.host ?? origin }
}

/// Root app state: holds the ``VoidbindEngine``, the enrolled identity (persisted
/// across launches), and the list of trusted sites. Views observe it; the real
/// engine work runs off the main thread and publishes back here.
///
/// The enrolment cert + user id are public assertions (not secret material — the
/// signing seed stays in the Secure Enclave), so they persist in `UserDefaults`.
@MainActor
final class AppModel: ObservableObject {

    enum Enrolment: Equatable {
        case none
        case enrolled(userId: String, cert: String)
    }

    @Published var enrolment: Enrolment = .none
    @Published var trustedSites: [TrustedSite] = []

    let engine: VoidbindEngine

    /// The per-RP approval policy + audit trail — the SAME commonMain brain the Android
    /// engine uses (`ApprovalPolicyManager`), so trust-on-first-use and the audit log
    /// behave identically on both platforms. Backed by the in-memory commonMain stores
    /// for now; persisting them across launches (Keychain/UserDefaults, mirroring the
    /// enc-key baseline in `VoidbindEngine`) is a documented follow-up.
    let policy: ApprovalPolicyManager

    private let defaults = UserDefaults.standard
    private enum Key { static let userId = "vb.userId", cert = "vb.cert" }

    init(engine: VoidbindEngine = VoidbindEngine(), preview: Bool = false) {
        self.engine = engine
        self.policy = ApprovalPolicyManager(
            policies: InMemorySitePolicyStore(),
            audit: InMemoryApprovalAuditLog(capacity: 500),
            clock: { KotlinLong(longLong: Int64(Date().timeIntervalSince1970)) }
        )
        if preview { return }
        if let userId = defaults.string(forKey: Key.userId),
           let cert = defaults.string(forKey: Key.cert) {
            enrolment = .enrolled(userId: userId, cert: cert)
        }
    }

    /// Whether the given RP host is trusted-on-first-use (streamlined) rather than always-ask.
    func isTrusted(_ rp: String) -> Bool {
        policy.policyFor(rp: rp)?.policy == ApprovalPolicy.trustedTofu
    }

    /// Whether the user pinned "always ask" for the given RP host.
    func isPinnedAlwaysAsk(_ rp: String) -> Bool {
        policy.policyFor(rp: rp)?.pinnedAlwaysAsk == true
    }

    /// Pin (or clear) "always ask" for an RP host. Pinning blocks silent trust-on-first-use.
    func setAlwaysAsk(_ rp: String, _ alwaysAsk: Bool) {
        if alwaysAsk { policy.setAlwaysAsk(rp: rp) } else { policy.trust(rp: rp) }
        objectWillChange.send()
    }

    /// The approval-activity log, newest first.
    func approvalActivity(limit: Int32 = 100) -> [ApprovalAuditEntry] {
        policy.auditEntries(limit: limit)
    }

    var isEnrolled: Bool { if case .enrolled = enrolment { return true } else { return false } }

    /// This device's enrolment cert, if enrolled — needed to sign a web-login approval.
    var cert: String? { if case let .enrolled(_, cert) = enrolment { return cert } else { return nil } }

    /// Persist a freshly enrolled identity and move to Home.
    func completeEnrolment(userId: String, cert: String) {
        defaults.set(userId, forKey: Key.userId)
        defaults.set(cert, forKey: Key.cert)
        enrolment = .enrolled(userId: userId, cert: cert)
    }

    /// Forget this identity on this device (Settings → sign out). Does not destroy
    /// the account — the recovery secret still restores it.
    func signOut() {
        defaults.removeObject(forKey: Key.userId)
        defaults.removeObject(forKey: Key.cert)
        enrolment = .none
        trustedSites = []
    }

    func recordLogin(origin: String) {
        trustedSites.removeAll { $0.origin == origin }
        trustedSites.insert(TrustedSite(origin: origin, lastUsed: Date()), at: 0)
    }
}
