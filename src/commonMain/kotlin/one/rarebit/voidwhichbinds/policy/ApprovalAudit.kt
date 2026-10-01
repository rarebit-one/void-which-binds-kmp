package one.rarebit.voidwhichbinds.policy

/** Whether the human approved or denied a login on the consent sheet. */
enum class ApprovalDecision { Approved, Denied }

/**
 * One immutable record in the **approval audit log** — the "who did I approve, and
 * when" trail. Appended once per approve/deny decision and never mutated. Pure data;
 * a [ApprovalAuditLog] holds the sequence.
 *
 * @param timestampSeconds unix seconds of the decision.
 * @param rp the relying party's stable identifier (its host) — the same key a
 *   [SitePolicy] uses.
 * @param audience the origin the login challenge bound (what the assertion authorises).
 * @param loginId the RP's short-lived login id for this request.
 * @param decision [ApprovalDecision.Approved] or [ApprovalDecision.Denied].
 * @param matchNumber the number the human tapped for a **number-matching (v2)** login,
 *   or null for a scanned (v1) login. Recorded so the audit trail shows which decoy/match
 *   was chosen.
 */
data class ApprovalAuditEntry(
    val timestampSeconds: Long,
    val rp: String,
    val audience: String,
    val loginId: String,
    val decision: ApprovalDecision,
    val matchNumber: Int? = null,
)

/**
 * The append-only audit trail. Implementations persist the entries (the app supplies
 * the platform-backed store; [InMemoryApprovalAuditLog] backs tests and previews).
 * [entries] returns newest-first, capped at [limit].
 */
interface ApprovalAuditLog {
    /** Append one immutable decision record. */
    fun append(entry: ApprovalAuditEntry)

    /** The most recent decisions, newest first, at most [limit]. */
    fun entries(limit: Int = 100): List<ApprovalAuditEntry>
}

/**
 * A per-RP policy store. A brand-new RP returns null from [get]. Implementations
 * persist across launches; [InMemorySitePolicyStore] backs tests and previews.
 */
interface SitePolicyStore {
    /** The remembered policy for [rp], or null if the RP has never been seen. */
    fun get(rp: String): SitePolicy?

    /** Persist (insert or replace) [policy]. */
    fun put(policy: SitePolicy)

    /** Every remembered policy (order unspecified). */
    fun all(): List<SitePolicy>

    /** Forget the policy for [rp] (e.g. when the site is revoked). */
    fun remove(rp: String)
}

/**
 * In-memory [SitePolicyStore] — pure, dependency-free, for tests and the preview
 * engine. The app supplies a persistent implementation.
 */
class InMemorySitePolicyStore : SitePolicyStore {
    private val byRp = mutableMapOf<String, SitePolicy>()

    override fun get(rp: String): SitePolicy? = byRp[rp]
    override fun put(policy: SitePolicy) {
        byRp[policy.rp] = policy
    }
    override fun all(): List<SitePolicy> = byRp.values.toList()
    override fun remove(rp: String) {
        byRp.remove(rp)
    }
}

/**
 * In-memory [ApprovalAuditLog] — a bounded ring keeping the most recent [capacity]
 * decisions. Pure, dependency-free, for tests and the preview engine. [entries]
 * returns newest first.
 */
class InMemoryApprovalAuditLog(private val capacity: Int = 500) : ApprovalAuditLog {
    private val log = ArrayDeque<ApprovalAuditEntry>()

    override fun append(entry: ApprovalAuditEntry) {
        log.addLast(entry)
        while (log.size > capacity) log.removeFirst()
    }

    override fun entries(limit: Int): List<ApprovalAuditEntry> = log.asReversed().take(limit)
}
