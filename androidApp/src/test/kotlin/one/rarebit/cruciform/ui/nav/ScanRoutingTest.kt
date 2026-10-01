package one.rarebit.cruciform.ui.nav

import one.rarebit.cruciform.domain.RETIRED_RECOVERY_SHEET
import one.rarebit.cruciform.domain.ScannedCode
import one.rarebit.cruciform.ui.flow.ScannedSecretViewModel
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class ScanRoutingTest {
    private val login = ScannedCode.WebLogin("https://rp.example.test", "L1", "void-which-binds:login?…")
    private val invite = ScannedCode.PairInvite("https://relay.example.test", "s1", "void-which-binds:pair?…")
    private val secret =
        ScannedCode.RecoverySecret("VOID-WHICH-BINDS1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0STSKA6C")
    private val gen1 =
        ScannedCode.RetiredRecoverySecret("HEYARR1QQQSYQCYQ5RQWZQFPG9SCRGWPUGPZYSNZS23V9CCRYDPK8QARC0S6E0UCU")
    private val junk = ScannedCode.Unknown("https://example.com")

    @Test
    fun `the general scanner keeps login and pairing, and says what it can't read`() {
        for (hasIdentity in listOf(false, true)) {
            assertEquals(ScanAction.OpenLogin(login), scanAction(login, ScanMode.ANY, hasIdentity))
            assertEquals(ScanAction.JoinPair(invite), scanAction(invite, ScanMode.ANY, hasIdentity))
            assertEquals(ScanAction.Reject(NOT_A_VOID_WHICH_BINDS_CODE), scanAction(junk, ScanMode.ANY, hasIdentity))
        }
    }

    @Test
    fun `a recovery sheet restores from onboarding and runs the drill once an identity exists`() {
        assertEquals(ScanAction.Restore(secret.raw), scanAction(secret, ScanMode.ANY, hasIdentity = false))
        assertEquals(ScanAction.Drill(secret.raw), scanAction(secret, ScanMode.ANY, hasIdentity = true))
    }

    @Test
    fun `a gen1 recovery sheet is refused as retired by either scanner`() {
        for (hasIdentity in listOf(false, true)) {
            for (mode in ScanMode.entries) {
                assertEquals(ScanAction.Reject(RETIRED_RECOVERY_SHEET), scanAction(gen1, mode, hasIdentity))
            }
        }
        assertFalse(gen1.toString().contains(gen1.raw))
    }

    @Test
    fun `the field's scanner hands a secret back and takes nothing else`() {
        for (hasIdentity in listOf(false, true)) {
            val mode = ScanMode.RECOVERY_SECRET
            assertEquals(ScanAction.ReturnSecret(secret.raw), scanAction(secret, mode, hasIdentity))
            for (other in listOf(login, invite, junk)) {
                assertEquals(ScanAction.Reject(NOT_A_RECOVERY_SECRET), scanAction(other, mode, hasIdentity))
            }
        }
    }

    @Test
    fun `no action prints the secret`() {
        val raw = secret.raw
        for (action in listOf(ScanAction.Restore(raw), ScanAction.Drill(raw), ScanAction.ReturnSecret(raw))) {
            assertFalse(action.toString().contains(secret.raw))
        }
    }

    @Test
    fun `the scanned secret is held until its field takes it`() {
        val holder = ScannedSecretViewModel()
        assertNull(holder.secret.value)

        holder.deliver(secret.raw)
        assertEquals(secret.raw, holder.secret.value)

        holder.consume()
        assertNull(holder.secret.value)
    }
}
