package one.rarebit.cruciform.domain

import one.rarebit.cruciform.domain.HomeSummary.Attention
import one.rarebit.cruciform.domain.HomeSummary.Status
import org.junit.Test
import kotlin.test.assertEquals

class HomeSummaryTest {
    private val ready = IdentityState.Active(
        identity = Identity("Pixel", "7C4A 91D2 0E8F 3B6A", "ed25519:00"),
        device = DeviceInfo("Pixel", "dev · A29F 67B1", HardwareBacking.STRONGBOX, biometricRequired = true),
        trustedSites = emptyList(),
        membership = MembershipHealth(renewsByLabel = "renews by 1 Dec 2026"),
    )

    @Test
    fun `a hardware-backed member with a checked backup is ready`() {
        assertEquals(HomeSummary(Status.READY, emptyList()), HomeSummary.of(ready))
        val tee = ready.copy(device = ready.device.copy(backing = HardwareBacking.TEE))
        assertEquals(Status.READY, HomeSummary.of(tee).status)
    }

    @Test
    fun `a lapsed device cannot sign in, and renewal is not offered for it`() {
        val lapsed = ready.copy(membership = MembershipHealth(renewalDue = true, lapsed = true))
        assertEquals(HomeSummary(Status.CANNOT_SIGN_IN, listOf(Attention.DEVICE_LAPSED)), HomeSummary.of(lapsed))
    }

    @Test
    fun `each pending chore needs attention, most pressing first`() {
        val all = ready.copy(
            device = ready.device.copy(backing = HardwareBacking.SOFTWARE),
            membership = ready.membership.copy(renewalDue = true),
            backup = BackupStatus(confirmPending = true),
        )
        assertEquals(
            HomeSummary(
                Status.NEEDS_ATTENTION,
                listOf(Attention.RENEW_DEVICE, Attention.CHECK_BACKUP, Attention.SOFTWARE_KEY),
            ),
            HomeSummary.of(all),
        )
    }

    @Test
    fun `a lapsed device still lists what else needs doing`() {
        val lapsed = ready.copy(
            membership = MembershipHealth(lapsed = true),
            backup = BackupStatus(confirmPending = true),
        )
        assertEquals(
            HomeSummary(Status.CANNOT_SIGN_IN, listOf(Attention.DEVICE_LAPSED, Attention.CHECK_BACKUP)),
            HomeSummary.of(lapsed),
        )
    }

    @Test
    fun `a yearly drill that is due stays in Manage, not on Home`() {
        val drill = ready.copy(backup = BackupStatus(lastCheckedLabel = "Checked 1 Jan 2025", drillDue = true))
        assertEquals(Status.READY, HomeSummary.of(drill).status)
    }
}
