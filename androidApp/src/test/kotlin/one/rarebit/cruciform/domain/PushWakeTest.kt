package one.rarebit.cruciform.domain

import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.testing.FakeBiometric
import one.rarebit.cruciform.testing.FakeTransport
import one.rarebit.cruciform.testing.InMemoryPrefs
import one.rarebit.cruciform.testing.InMemorySealer
import one.rarebit.cruciform.testing.SoftwareDeviceKeys
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.auth.PossessionProof
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.net.HttpResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The push-login wake registration, through [DeviceVoidbindEngine] and [PushWake].
 *
 * The C2 regression (2026-10-17): Cruciform 1.0.0 registered with a bare cert, which the
 * void-which-binds-go v0.19.x notify plane refuses (`ErrPossessionRequired`), so no phone
 * could be woken for a push login. Registration now proves possession of the device key
 * and presents the device's ops, and is not repeated on every app open.
 */
class PushWakeTest {

    private val store = IdentityStore(InMemoryPrefs(), InMemorySealer())
    private val transport = FakeTransport()
    private val keys = SoftwareDeviceKeys(HardwareBacking.TEE)
    private var notify = NOTIFY
    private var now = NOW

    private fun engine() = DeviceVoidbindEngine(
        store = store,
        policyStore = ApprovalPolicyStore(InMemoryPrefs()),
        transport = transport,
        biometric = FakeBiometric(),
        relay = { "https://relay.example.test" },
        notify = { notify },
        clock = { now },
        membershipRps = emptyList(),
        deviceKeys = keys,
        defaultDeviceName = { "Test Phone" },
    )

    private fun accepted(expiresAt: Long = NOW + 30 * DAY) = HttpResponse(
        200,
        """{"user_id":"u","device_key":"d","channel":"ntfy","expires_at":$expiresAt}""".encodeToByteArray(),
    )

    @Test
    fun `registration proves possession of the device key and presents its ops`() = runTest {
        val engine = engine()
        engine.createIdentity()
        var sent: Map<String, Any> = emptyMap()
        transport.handler = { _, _, body ->
            sent = MiniJson.parseObject(body!!.decodeToString())
            accepted()
        }

        assertEquals(EngineResult.Ready(Unit), engine.registerForPush(ENDPOINT))

        val cert = sent["cert"] as String
        assertEquals(ENDPOINT, sent["endpoint"])
        // The proof verifies against THIS device's key, over the very cert sent.
        PossessionProof.verify(sent["possession"] as String, keys.publicKey, cert, NOW, Ed25519Engine.verifier())
        @Suppress("UNCHECKED_CAST")
        val ops = sent["ops"] as List<String>
        assertTrue("the device presents the ops it knows, its own admission included", cert in ops)
    }

    @Test
    fun `registration is not repeated on every open while the subscription stands`() = runTest {
        val engine = engine()
        engine.createIdentity()
        transport.handler = { _, _, _ -> accepted() }

        engine.registerForPush(ENDPOINT)
        engine.registerForPush(ENDPOINT) // the next app open: nothing to sign, nothing to send
        assertEquals(1, transport.requests.size)

        engine.registerForPush("$ENDPOINT-rotated") // the distributor minted a new endpoint
        assertEquals(2, transport.requests.size)

        now = NOW + 24 * DAY // within a week of lapsing: renew
        engine.registerForPush("$ENDPOINT-rotated")
        assertEquals(3, transport.requests.size)

        notify = "https://other-plane.example.test" // Settings → Push plane changed
        engine.registerForPush("$ENDPOINT-rotated")
        assertEquals(4, transport.requests.size)
    }

    @Test
    fun `a refused registration is not remembered, so the next open tries again`() = runTest {
        val engine = engine()
        engine.createIdentity()
        transport.handler = { _, _, _ -> HttpResponse(401, ByteArray(0)) }
        failure(engine.registerForPush(ENDPOINT))

        transport.handler = { _, _, _ -> accepted() }
        assertEquals(EngineResult.Ready(Unit), engine.registerForPush(ENDPOINT))
        assertEquals(2, transport.requests.size)
    }

    @Test
    fun `unregistering proves possession too and forgets the registration`() = runTest {
        val engine = engine()
        engine.createIdentity()
        var deleted: Map<String, Any> = emptyMap()
        transport.handler = { method, _, body ->
            if (method == "DELETE") {
                deleted = MiniJson.parseObject(body!!.decodeToString())
                HttpResponse(204, ByteArray(0))
            } else {
                accepted()
            }
        }
        engine.registerForPush(ENDPOINT)

        assertEquals(EngineResult.Ready(Unit), engine.unregisterFromPush())
        assertTrue("an unsubscribe carries a proof", (deleted["possession"] as String).isNotEmpty())
        engine.registerForPush(ENDPOINT) // forgotten: the next open registers again
        assertEquals(3, transport.requests.size)
    }

    private companion object {
        const val NOW = 1_800_000_000L
        const val DAY = 24L * 60 * 60
        const val NOTIFY = "https://notify.example.test"
        const val ENDPOINT = "https://push.example.test/up/abc"
    }
}
