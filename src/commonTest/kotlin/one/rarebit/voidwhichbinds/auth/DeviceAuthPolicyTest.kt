package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [DeviceAuthPolicy]: re-mint and retry ONCE on a `401`, pass everything else
 * through, and never loop.
 */
class DeviceAuthPolicyTest {

    private val cert = "eyJ2IjoyfQ.c2ln" // any non-empty cert token: the policy never parses it
    private val g = Ed25519Engine.generate()
    private var signCount = 0
    private val signer = Ed25519Signer {
        signCount++
        Ed25519Engine.sign(g.privateSeed, it)
    }

    private class Resp(val status: Int, val header: String)

    private fun drive(vararg statuses: Int): Pair<List<Resp>, Resp> {
        // A ticking clock: Ed25519 is deterministic, so a re-mint at the SAME second
        // would be byte-identical — the fresh-proof assertion needs time to move.
        var clock = 1_700_000_000L
        val cred = DeviceCredential(cert, signer, { clock++ })
        val sent = mutableListOf<Resp>()
        var i = 0
        val final = DeviceAuthPolicy.execute(cred, statusOf = { it.status }) { header ->
            Resp(statuses[i++], header).also { sent += it }
        }
        return sent to final
    }

    @Test
    fun theDecisionIsPure() {
        assertEquals(DeviceAuthPolicy.Next.REFRESH_AND_RETRY, DeviceAuthPolicy.next(401, attempt = 1))
        assertEquals(DeviceAuthPolicy.Next.DONE, DeviceAuthPolicy.next(401, attempt = 2))
        assertEquals(DeviceAuthPolicy.Next.DONE, DeviceAuthPolicy.next(200, attempt = 1))
        assertEquals(DeviceAuthPolicy.Next.DONE, DeviceAuthPolicy.next(403, attempt = 1))
        assertEquals(DeviceAuthPolicy.Next.DONE, DeviceAuthPolicy.next(500, attempt = 1))
    }

    @Test
    fun aSuccessIsSentOnceWithADeviceHeader() {
        val (sent, final) = drive(200)
        assertEquals(1, sent.size)
        assertEquals(200, final.status)
        assertEquals(1, signCount)
        assertEquals(true, DeviceCredential.isDeviceHeader(final.header))
    }

    @Test
    fun a401ReMintsAndRetriesExactlyOnce() {
        val (sent, final) = drive(401, 200)
        assertEquals(2, sent.size)
        assertEquals(200, final.status)
        assertEquals(2, signCount, "one mint, one forced re-mint")
        assertEquals(true, sent[0].header != sent[1].header, "the retry carries a fresh proof")
    }

    @Test
    fun aSecond401IsSurfacedAsIs() {
        val (sent, final) = drive(401, 401, 200)
        assertEquals(2, sent.size, "never a third attempt")
        assertEquals(401, final.status)
    }

    @Test
    fun non401RefusalsAreNotRetried() {
        val (sent, final) = drive(403, 200)
        assertEquals(1, sent.size)
        assertEquals(403, final.status)
        assertEquals(1, signCount)
    }
}
