package one.rarebit.cruciform.domain

import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.testing.FakeBiometric
import one.rarebit.cruciform.testing.FakeTransport
import one.rarebit.cruciform.testing.InMemoryPrefs
import one.rarebit.cruciform.testing.InMemorySealer
import one.rarebit.cruciform.testing.SoftwareDeviceKeys
import one.rarebit.voidwhichbinds.net.HttpResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [DeviceVoidbindEngine.refusePairing]: "No, cancel" on the Verify screen (void-which-binds-go
 * ADR-0012). Behind the biometric it signs and posts a refusal to the invite's relay
 * session, so the new device stops at once; a cancelled prompt sends nothing. Either
 * way the invite can no longer be authorised. Same seams as [DeviceVoidbindEngineTest].
 */
class DeviceVoidbindEngineRefusalTest {

    private val transport = FakeTransport()
    private val biometric = FakeBiometric()

    private fun engine() = DeviceVoidbindEngine(
        store = IdentityStore(InMemoryPrefs(), InMemorySealer()),
        policyStore = ApprovalPolicyStore(InMemoryPrefs()),
        transport = transport,
        biometric = biometric,
        relay = { RELAY },
        notify = { "" },
        clock = { NOW },
        membershipRps = emptyList(),
        deviceKeys = SoftwareDeviceKeys(HardwareBacking.TEE),
        defaultDeviceName = { "Test Phone" },
    )

    /** A relay that opens sessions and stores slots — enough to mint an invite and refuse it. */
    private fun relayServes() {
        transport.handler = { method, url, _ ->
            when {
                method == "POST" && url == "$RELAY/v1/sessions" ->
                    HttpResponse(200, """{"session_id":"s1"}""".encodeToByteArray())

                method == "PUT" -> HttpResponse(204, ByteArray(0))

                else -> HttpResponse(404, ByteArray(0))
            }
        }
    }

    @Test
    fun `refusePairing signs and posts a refusal behind the biometric`() = runTest {
        val engine = engine()
        engine.createIdentity()
        relayServes()
        engine.startPairInvite()
        biometric.prompts.clear()
        transport.requests.clear()

        assertEquals(EngineResult.Ready(Unit), engine.refusePairing())

        assertEquals(listOf("Decline new device"), biometric.prompts)
        assertEquals(listOf("PUT $RELAY/v1/sessions/s1/initiator/refuse"), transport.requests)
        // The invite is over: nothing can authorise it now.
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.confirmPairing()).kind)
    }

    @Test
    fun `refusePairing with the biometric cancelled sends nothing`() = runTest {
        val engine = engine()
        engine.createIdentity()
        relayServes()
        engine.startPairInvite()
        transport.requests.clear()
        biometric.presence = false

        assertEquals(EngineFailure.Kind.CANCELLED, failure(engine.refusePairing()).kind)

        assertTrue(transport.requests.none { it.startsWith("PUT") })
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.confirmPairing()).kind)
    }

    @Test
    fun `refusePairing with nothing in progress is an internal failure`() = runTest {
        val engine = engine()
        engine.createIdentity()
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.refusePairing()).kind)
    }

    private companion object {
        const val NOW = 1_800_000_000L
        const val RELAY = "https://relay.example.test/pair"
    }
}
