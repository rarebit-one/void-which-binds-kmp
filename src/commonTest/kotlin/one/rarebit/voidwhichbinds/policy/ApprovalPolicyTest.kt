package one.rarebit.voidwhichbinds.policy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The per-RP approval-policy state machine + audit log. Pure commonMain logic — no
 * device, no network — so a green run proves TOFU trust, the always-ask override, and
 * the audit trail behave, independent of any platform persistence.
 */
class ApprovalPolicyTest {

    private val RP = "homelab.example"
    private val AUD = "https://homelab.example:8443"

    // --- TOFU transitions (pure machine) --------------------------------------

    @Test
    fun brandNewSiteRequiresTheConsentSheet() {
        assertTrue(ApprovalPolicyMachine.requiresConsentSheet(null))
    }

    @Test
    fun firstSuccessfulApprovalTrustsTheSiteOnFirstUse() {
        val trusted = ApprovalPolicyMachine.onSuccessfulApproval(current = null, rp = RP, at = 1_000L)
        assertEquals(ApprovalPolicy.TrustedTofu, trusted.policy)
        assertEquals(1_000L, trusted.firstTrustedAt)
        assertFalse(trusted.pinnedAlwaysAsk)
        assertFalse(ApprovalPolicyMachine.requiresConsentSheet(trusted), "a trusted site skips the sheet")
    }

    @Test
    fun aSecondApprovalKeepsTheOriginalFirstTrustedTimestamp() {
        val first = ApprovalPolicyMachine.onSuccessfulApproval(null, RP, at = 1_000L)
        val second = ApprovalPolicyMachine.onSuccessfulApproval(first, RP, at = 5_000L)
        assertEquals(ApprovalPolicy.TrustedTofu, second.policy)
        assertEquals(1_000L, second.firstTrustedAt, "firstTrustedAt must not move on re-approval")
    }

    // --- Always-ask override --------------------------------------------------

    @Test
    fun pinnedAlwaysAskIsNotSilentlyUpgradedByTofu() {
        val pinned = ApprovalPolicyMachine.pinAlwaysAsk(RP)
        assertEquals(ApprovalPolicy.AlwaysAsk, pinned.policy)
        assertTrue(pinned.pinnedAlwaysAsk)

        // A successful login must NOT auto-trust a pinned site.
        val afterLogin = ApprovalPolicyMachine.onSuccessfulApproval(pinned, RP, at = 2_000L)
        assertEquals(ApprovalPolicy.AlwaysAsk, afterLogin.policy, "the pin wins over trust-on-first-use")
        assertTrue(afterLogin.pinnedAlwaysAsk)
        assertTrue(ApprovalPolicyMachine.requiresConsentSheet(afterLogin))
    }

    @Test
    fun userCanExplicitlyTrustThenPinAgain() {
        val trusted = ApprovalPolicyMachine.trust(current = null, rp = RP, at = 100L)
        assertEquals(ApprovalPolicy.TrustedTofu, trusted.policy)
        assertFalse(trusted.pinnedAlwaysAsk)

        val repinned = ApprovalPolicyMachine.pinAlwaysAsk(RP)
        assertEquals(ApprovalPolicy.AlwaysAsk, repinned.policy)
        assertTrue(repinned.pinnedAlwaysAsk)

        // And after re-pinning, TOFU still must not re-trust.
        val afterLogin = ApprovalPolicyMachine.onSuccessfulApproval(repinned, RP, at = 200L)
        assertEquals(ApprovalPolicy.AlwaysAsk, afterLogin.policy)
    }

    // --- In-memory stores -----------------------------------------------------

    @Test
    fun policyStoreRoundTrips() {
        val store = InMemorySitePolicyStore()
        assertNull(store.get(RP))
        val p = SitePolicy(RP, ApprovalPolicy.TrustedTofu, firstTrustedAt = 9L)
        store.put(p)
        assertEquals(p, store.get(RP))
        assertEquals(listOf(p), store.all())
        store.remove(RP)
        assertNull(store.get(RP))
    }

    @Test
    fun auditLogIsNewestFirstAndBounded() {
        val log = InMemoryApprovalAuditLog(capacity = 3)
        repeat(5) { i ->
            log.append(ApprovalAuditEntry(i.toLong(), RP, AUD, "L$i", ApprovalDecision.Approved))
        }
        val entries = log.entries()
        assertEquals(3, entries.size, "bounded to capacity")
        assertEquals(listOf("L4", "L3", "L2"), entries.map { it.loginId }, "newest first, oldest evicted")
    }

    @Test
    fun auditLogPreservesMatchNumberAndDecision() {
        val log = InMemoryApprovalAuditLog()
        log.append(ApprovalAuditEntry(1L, RP, AUD, "L1", ApprovalDecision.Approved, matchNumber = 42))
        log.append(ApprovalAuditEntry(2L, RP, AUD, "L2", ApprovalDecision.Denied))
        val entries = log.entries()
        assertEquals(ApprovalDecision.Denied, entries[0].decision)
        assertNull(entries[0].matchNumber)
        assertEquals(ApprovalDecision.Approved, entries[1].decision)
        assertEquals(42, entries[1].matchNumber)
    }

    // --- Manager (end-to-end over the stores) ---------------------------------

    private fun manager(now: Long = 1_000L): Pair<ApprovalPolicyManager, LongArray> {
        val clockBox = longArrayOf(now)
        val m = ApprovalPolicyManager(InMemorySitePolicyStore(), InMemoryApprovalAuditLog()) { clockBox[0] }
        return m to clockBox
    }

    @Test
    fun managerTrustsOnFirstUseAndLogsTheApproval() {
        val (m, _) = manager()
        assertTrue(m.requiresConsentSheet(RP), "unseen RP asks")
        assertEquals(ApprovalPolicy.AlwaysAsk, m.effectivePolicy(RP))

        val next = m.recordApproval(RP, AUD, "L1")
        assertEquals(ApprovalPolicy.TrustedTofu, next.policy)
        assertFalse(m.requiresConsentSheet(RP), "trusted after first approval")

        val audit = m.auditEntries()
        assertEquals(1, audit.size)
        assertEquals(ApprovalDecision.Approved, audit[0].decision)
        assertEquals("L1", audit[0].loginId)
    }

    @Test
    fun managerHonoursAlwaysAskAcrossApprovals() {
        val (m, _) = manager()
        m.setAlwaysAsk(RP)
        assertTrue(m.requiresConsentSheet(RP))

        val next = m.recordApproval(RP, AUD, "L1")
        assertEquals(ApprovalPolicy.AlwaysAsk, next.policy, "pinned always-ask survives an approval")
        assertTrue(m.requiresConsentSheet(RP), "still asks after approval")
    }

    @Test
    fun managerRecordsDenialsWithoutChangingTrust() {
        val (m, _) = manager()
        m.recordDenial(RP, AUD, "L1", matchNumber = 7)
        assertNull(m.policyFor(RP), "a denial creates no trust")
        assertTrue(m.requiresConsentSheet(RP))

        val audit = m.auditEntries()
        assertEquals(1, audit.size)
        assertEquals(ApprovalDecision.Denied, audit[0].decision)
        assertEquals(7, audit[0].matchNumber)
    }

    @Test
    fun managerTrustAndForget() {
        val (m, _) = manager()
        m.trust(RP)
        assertEquals(ApprovalPolicy.TrustedTofu, m.effectivePolicy(RP))
        assertFalse(m.requiresConsentSheet(RP))

        m.forget(RP)
        assertNull(m.policyFor(RP))
        assertTrue(m.requiresConsentSheet(RP), "forgotten site is back to always-ask")
    }

    @Test
    fun auditTimestampsUseTheInjectedClock() {
        val (m, clock) = manager(now = 500L)
        m.recordApproval(RP, AUD, "L1")
        clock[0] = 900L
        m.recordDenial(RP, AUD, "L2")
        val audit = m.auditEntries()
        assertEquals(900L, audit[0].timestampSeconds)
        assertEquals(500L, audit[1].timestampSeconds)
    }
}
