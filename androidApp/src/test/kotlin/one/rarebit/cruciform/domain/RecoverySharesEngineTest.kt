package one.rarebit.cruciform.domain

import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.platform.StrongAuth
import one.rarebit.cruciform.testing.FakeBiometric
import one.rarebit.cruciform.testing.FakeTransport
import one.rarebit.cruciform.testing.InMemoryPrefs
import one.rarebit.cruciform.testing.InMemorySealer
import one.rarebit.cruciform.testing.SoftwareDeviceKeys
import one.rarebit.voidwhichbinds.RecoveryShares
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.test.assertFailsWith

/**
 * [DeviceVoidbindEngine.splitRecoverySecret] (Settings → Split into shares) over the
 * same test seams as [DeviceVoidbindEngineTest]: the kept recovery secret split into
 * the Void-Which-Binds SLIP-39 profile (void-which-binds-go ADR-0011, any 2 of 3), behind a strong
 * biometric, checked with the library's real combine.
 */
class RecoverySharesEngineTest {

    private val store = IdentityStore(InMemoryPrefs(), InMemorySealer())
    private val biometric = FakeBiometric()

    private fun engine() = DeviceVoidbindEngine(
        store = store,
        policyStore = ApprovalPolicyStore(InMemoryPrefs()),
        transport = FakeTransport(),
        biometric = biometric,
        relay = { "https://relay.example.test/pair" },
        clock = { NOW },
        membershipRps = emptyList(),
        deviceKeys = SoftwareDeviceKeys(),
        defaultDeviceName = { "Test Phone" },
    )

    @Test
    fun `splitting the kept secret needs a strong biometric, never the PIN`() = runTest {
        val engine = engine()
        ready(engine.createIdentity())
        biometric.prompts.clear()

        biometric.strong = StrongAuth.CANCELLED
        assertEquals(EngineFailure.Kind.CANCELLED, failure(engine.splitRecoverySecret()).kind)

        // A PIN would pass the ordinary presence check; the kept secret stays sealed.
        biometric.presence = true
        biometric.strong = StrongAuth.UNAVAILABLE
        val f = failure(engine.splitRecoverySecret())
        assertEquals(EngineFailure.Kind.NOT_YET, f.kind)
        assertTrue(f.message.contains("PIN can't authorise it"))

        biometric.strong = StrongAuth.SUCCESS
        assertEquals(3, ready(engine.splitRecoverySecret()).size)
        assertEquals(List(3) { "Split into recovery shares" }, biometric.prompts)
    }

    @Test
    fun `a device that keeps no copy is refused before any prompt`() = runTest {
        biometric.strong = StrongAuth.CANCELLED // declined at create: the phone keeps no copy
        val engine = engine()
        ready(engine.createIdentity())
        biometric.strong = StrongAuth.SUCCESS
        biometric.prompts.clear()

        val f = failure(engine.splitRecoverySecret())

        assertEquals(EngineFailure.Kind.NOT_YET, f.kind)
        assertEquals("This phone keeps no copy of the recovery secret.", f.message)
        assertTrue(biometric.prompts.isEmpty())
    }

    @Test
    fun `any two of the shares combine back to the kept secret`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())

        val shares = ready(engine.splitRecoverySecret())

        assertEquals(3, shares.size)
        assertTrue(shares.all { it.split(" ").size == 33 })
        for ((a, b) in listOf(0 to 1, 0 to 2, 2 to 1)) {
            assertEquals(backup.rawSecret, RecoveryShares.combine(listOf(shares[a], shares[b])).format())
        }
        assertEquals(1, store.knownOps().size) // splitting signs nothing
        assertTrue(store.hasUserKey()) // and revokes nothing
    }

    @Test
    fun `each split is a fresh set that does not mix with another`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())

        val first = ready(engine.splitRecoverySecret())
        val second = ready(engine.splitRecoverySecret())

        assertTrue(first.intersect(second.toSet()).isEmpty())
        assertEquals(backup.rawSecret, RecoveryShares.combine(second.take(2)).format())
        assertFailsWith<IllegalArgumentException> { RecoveryShares.combine(listOf(first[0], second[1])) }
    }

    private companion object {
        const val NOW = 1_800_000_000L
    }
}
