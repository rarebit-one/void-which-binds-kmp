package one.rarebit.cruciform.domain

import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.testing.FakeBiometric
import one.rarebit.cruciform.testing.FakeTransport
import one.rarebit.cruciform.testing.InMemoryPrefs
import one.rarebit.cruciform.testing.InMemorySealer
import one.rarebit.cruciform.testing.SoftwareDeviceKeys
import one.rarebit.voidwhichbinds.Invite
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.UserIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Gen2 Cruciform has no gen1 reader (void-which-binds-go ADR-0022): a `heyarr1…`
 * recovery sheet is refused with a message that says it was retired (the library's
 * `RecoverySecret.GenerationRetiredException`), and a `voidbind:` login or pairing
 * code is just not a code. Same seams as [DeviceVoidbindEngineTest].
 */
class DeviceVoidbindEngineGen1Test {

    private val store = IdentityStore(InMemoryPrefs(), InMemorySealer())

    private fun engine() = DeviceVoidbindEngine(
        store = store,
        policyStore = ApprovalPolicyStore(InMemoryPrefs()),
        transport = FakeTransport(),
        biometric = FakeBiometric(),
        relay = { "https://relay.example.test/pair" },
        notify = { "" },
        clock = { 1_800_000_000L },
        membershipRps = emptyList(),
        deviceKeys = SoftwareDeviceKeys(HardwareBacking.TEE),
        defaultDeviceName = { "Test Phone" },
    )

    @Test
    fun `restoreIdentity with a gen1 sheet says it was retired and provisions nothing`() = runTest {
        val f = failure(engine().restoreIdentity(GEN1_SECRET))

        assertEquals(RETIRED_RECOVERY_SHEET, f.message)
        assertEquals(EngineFailure.Kind.NOT_YET, f.kind)
        assertFalse(f.retryable)
        assertFalse(store.isProvisioned())
    }

    @Test
    fun `verifying a gen1 sheet says it was retired and records nothing`() = runTest {
        val engine = engine()
        ready(engine.createIdentity())

        assertEquals(RETIRED_RECOVERY_SHEET, failure(engine.verifyRecoverySecret(GEN1_SECRET.uppercase())).message)
        assertTrue(active(engine).backup.confirmPending)
    }

    @Test
    fun `parseScanned names a gen1 recovery sheet as retired, never as a secret`() {
        val engine = engine()

        for (scanned in listOf(GEN1_SECRET, GEN1_SECRET.uppercase())) {
            assertEquals(ScannedCode.RetiredRecoverySecret(scanned), engine.parseScanned(scanned))
        }
        assertFalse(ScannedCode.RetiredRecoverySecret(GEN1_SECRET).toString().contains(GEN1_SECRET))
    }

    @Test
    fun `parseScanned refuses a gen1 voidbind login or pairing code`() {
        val engine = engine()
        val login = LoginQr.encode("https://rp.example.test", "L1").replaceFirst("void-which-binds:", "voidbind:")
        val usr = UserIdentity.create().userId.render()
        val invite = Invite.encode("https://relay.example.test/pair", "sess1", ByteArray(32) { it.toByte() }, usr)
            .replaceFirst("void-which-binds:", "voidbind:")

        assertEquals(ScannedCode.Unknown(login), engine.parseScanned(login))
        assertEquals(ScannedCode.Unknown(invite), engine.parseScanned(invite))
    }

    private companion object {
        /** A valid gen1 (`heyarr1…`) recovery secret, checksum and all: retired at ADR-0022. */
        const val GEN1_SECRET = "heyarr1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6e0ucu"
    }
}
