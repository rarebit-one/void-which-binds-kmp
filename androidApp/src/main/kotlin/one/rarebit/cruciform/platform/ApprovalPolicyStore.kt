package one.rarebit.cruciform.platform

import android.content.Context
import android.content.SharedPreferences
import one.rarebit.voidwhichbinds.policy.ApprovalAuditEntry
import one.rarebit.voidwhichbinds.policy.ApprovalAuditLog
import one.rarebit.voidwhichbinds.policy.ApprovalDecision
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy
import one.rarebit.voidwhichbinds.policy.SitePolicy
import one.rarebit.voidwhichbinds.policy.SitePolicyStore

/**
 * SharedPreferences-backed persistence for per-RP approval policy + the approval
 * audit log — the Android `actual` for the commonMain [SitePolicyStore] and
 * [ApprovalAuditLog] seams. Like [IdentityStore], this is app plumbing: the library
 * models the policy/audit types but persists nothing itself.
 *
 * All of this is **public, non-secret** consent state (which sites the user trusts,
 * and a decision log of rp/audience/login-id/decision) — none of it can authenticate
 * as the user — so it lives in plain prefs, alongside the trusted-site list, not in
 * the hardware-sealed [SealedSecretStore]. Records are line-delimited with a unit
 * separator between fields, the same shape as [IdentityStore]'s trusted-sites blob.
 */
class ApprovalPolicyStore(private val prefs: SharedPreferences) :
    SitePolicyStore,
    ApprovalAuditLog {

    constructor(context: Context) : this(context.getSharedPreferences("void-which-binds.policy", Context.MODE_PRIVATE))

    // --- SitePolicyStore ------------------------------------------------------

    override fun get(rp: String): SitePolicy? = readPolicies()[rp]

    override fun put(policy: SitePolicy) {
        val next = readPolicies().toMutableMap().apply { put(policy.rp, policy) }
        writePolicies(next.values)
    }

    override fun all(): List<SitePolicy> = readPolicies().values.toList()

    override fun remove(rp: String) {
        val next = readPolicies().toMutableMap().apply { remove(rp) }
        writePolicies(next.values)
    }

    private fun readPolicies(): Map<String, SitePolicy> =
        (prefs.getString(KEY_POLICIES, "") ?: "").split(REC).filter { it.isNotBlank() }.mapNotNull { line ->
            val p = line.split(SEP)
            if (p.size < 4) return@mapNotNull null
            val policy = runCatching { ApprovalPolicy.valueOf(p[1]) }.getOrNull() ?: return@mapNotNull null
            val firstTrustedAt = p[3].toLongOrNull()
            SitePolicy(
                rp = p[0],
                policy = policy,
                pinnedAlwaysAsk = p[2].toBoolean(),
                firstTrustedAt = firstTrustedAt,
            )
        }.associateBy { it.rp }

    private fun writePolicies(values: Collection<SitePolicy>) {
        val blob = values.joinToString(REC) {
            listOf(
                it.rp,
                it.policy.name,
                it.pinnedAlwaysAsk.toString(),
                it.firstTrustedAt?.toString() ?: "",
            ).joinToString(SEP)
        }
        prefs.edit().putString(KEY_POLICIES, blob).apply()
    }

    // --- ApprovalAuditLog -----------------------------------------------------

    override fun append(entry: ApprovalAuditEntry) {
        val current = readAudit()
        val next = (current + entry).takeLast(CAP)
        writeAudit(next)
    }

    override fun entries(limit: Int): List<ApprovalAuditEntry> = readAudit().asReversed().take(limit)

    private fun readAudit(): List<ApprovalAuditEntry> =
        (prefs.getString(KEY_AUDIT, "") ?: "").split(REC).filter { it.isNotBlank() }.mapNotNull { line ->
            val p = line.split(SEP)
            if (p.size < 5) return@mapNotNull null
            val ts = p[0].toLongOrNull() ?: return@mapNotNull null
            val decision = runCatching { ApprovalDecision.valueOf(p[4]) }.getOrNull() ?: return@mapNotNull null
            ApprovalAuditEntry(
                timestampSeconds = ts,
                rp = p[1],
                audience = p[2],
                loginId = p[3],
                decision = decision,
                matchNumber = p.getOrNull(5)?.toIntOrNull(),
            )
        }

    private fun writeAudit(entries: List<ApprovalAuditEntry>) {
        val blob = entries.joinToString(REC) {
            listOf(
                it.timestampSeconds.toString(),
                it.rp,
                it.audience,
                it.loginId,
                it.decision.name,
                it.matchNumber?.toString() ?: "",
            ).joinToString(SEP)
        }
        prefs.edit().putString(KEY_AUDIT, blob).apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val KEY_POLICIES = "policies"
        const val KEY_AUDIT = "audit"
        const val REC = "\n"
        const val SEP = "" // unit separator, as IdentityStore uses between fields
        const val CAP = 500
    }
}
