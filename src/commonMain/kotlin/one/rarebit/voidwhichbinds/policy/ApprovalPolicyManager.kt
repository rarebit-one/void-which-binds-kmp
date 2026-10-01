package one.rarebit.voidwhichbinds.policy

/**
 * The **app-facing coordinator** for per-RP approval policy + the approval audit log.
 * It binds the pure [ApprovalPolicyMachine] transitions to a persistent
 * [SitePolicyStore] and [ApprovalAuditLog], and is the single seam the platform
 * engines (Android `DeviceVoidbindEngine`, iOS `VoidbindEngine`) call.
 *
 * It holds NO crypto and touches NO network — it records consent decisions and
 * remembers trust. The hardware-gated signature is produced by
 * [one.rarebit.voidwhichbinds.flow.LoginApproval] exactly as before; the engine calls
 * [recordApproval] / [recordDenial] around that unchanged call.
 *
 * @param policies where per-RP [SitePolicy] is persisted.
 * @param audit where each decision is appended.
 * @param clock unix-seconds source (injected for testability).
 */
class ApprovalPolicyManager(
    private val policies: SitePolicyStore,
    private val audit: ApprovalAuditLog,
    private val clock: () -> Long,
) {
    /** The remembered policy for [rp], or null if it has never been approved. */
    fun policyFor(rp: String): SitePolicy? = policies.get(rp)

    /** The effective policy an approval sheet shows: [ApprovalPolicy.AlwaysAsk] for an unseen RP. */
    fun effectivePolicy(rp: String): ApprovalPolicy = policies.get(rp)?.policy ?: ApprovalPolicy.AlwaysAsk

    /**
     * Whether the full consent sheet must be shown for [rp]. True for a brand-new or
     * always-ask RP; false only once the site is trust-on-first-use. The crypto path
     * (biometric-gated signature) runs regardless — this only governs UI friction.
     */
    fun requiresConsentSheet(rp: String): Boolean = ApprovalPolicyMachine.requiresConsentSheet(policies.get(rp))

    /** All remembered site policies (for the Settings trusted-sites view). */
    fun allPolicies(): List<SitePolicy> = policies.all()

    /** The user pins [rp] to "always ask" — force the full sheet, block silent TOFU re-trust. */
    fun setAlwaysAsk(rp: String) {
        policies.put(ApprovalPolicyMachine.pinAlwaysAsk(rp))
    }

    /** The user explicitly trusts [rp] (clears any always-ask pin). */
    fun trust(rp: String) {
        policies.put(ApprovalPolicyMachine.trust(policies.get(rp), rp, clock()))
    }

    /** Forget [rp]'s policy (revoking the site). Does not erase past audit entries. */
    fun forget(rp: String) = policies.remove(rp)

    /**
     * Record a **successful** approval: append an [ApprovalDecision.Approved] audit
     * entry and apply trust-on-first-use to the site policy. Returns the resulting
     * [SitePolicy] (now trusted, unless the user had pinned always-ask). Call this
     * AFTER the assertion is accepted by the RP.
     */
    fun recordApproval(rp: String, audience: String, loginId: String, matchNumber: Int? = null): SitePolicy {
        val at = clock()
        audit.append(
            ApprovalAuditEntry(at, rp, audience, loginId, ApprovalDecision.Approved, matchNumber),
        )
        val next = ApprovalPolicyMachine.onSuccessfulApproval(policies.get(rp), rp, at)
        policies.put(next)
        return next
    }

    /**
     * Record a **denied** login: append an [ApprovalDecision.Denied] audit entry. A
     * denial never changes trust (nothing was signed), so the site policy is untouched.
     */
    fun recordDenial(rp: String, audience: String, loginId: String, matchNumber: Int? = null) {
        audit.append(
            ApprovalAuditEntry(clock(), rp, audience, loginId, ApprovalDecision.Denied, matchNumber),
        )
    }

    /** The most recent decisions, newest first, at most [limit]. */
    fun auditEntries(limit: Int = 100): List<ApprovalAuditEntry> = audit.entries(limit)
}
