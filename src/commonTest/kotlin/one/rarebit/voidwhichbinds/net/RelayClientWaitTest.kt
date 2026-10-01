package one.rarebit.voidwhichbinds.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * [RelayClient.fetch]'s wait bound is what decides whether an initiator outlives a
 * human-paced responder. A fake transport answers 404 for a scripted number of polls
 * (virtual time — no real sleeping) so the bound is asserted exactly.
 */
class RelayClientWaitTest {

    /** 404 until [appearAfterPolls] polls have happened, then 200 with [body]. Sleeps are counted, not taken. */
    private class ScriptedTransport(
        private val appearAfterPolls: Int,
        private val body: ByteArray = "peer".encodeToByteArray(),
    ) : HttpTransport {
        var polls = 0
        var sleptMillis = 0L
        override fun get(url: String): HttpResponse {
            polls++
            return if (polls > appearAfterPolls) HttpResponse(200, body) else HttpResponse(404, ByteArray(0))
        }
        override fun post(url: String, body: ByteArray?, contentType: String?) = HttpResponse(200, ByteArray(0))
        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(204, ByteArray(0))
        override fun sleep(millis: Long) {
            sleptMillis += millis
        }
    }

    private fun client(t: HttpTransport, maxWaitMillis: Long) = RelayClient(
        t,
        "http://relay.test/pair",
        "sess",
        RelayClient.ROLE_INITIATOR,
        pollIntervalMillis = 1_000,
        maxWaitMillis = maxWaitMillis,
    )

    @Test
    fun theDefaultBoundIsSixtySeconds() {
        assertEquals(60_000L, RelayClient.DEFAULT_MAX_WAIT_MILLIS)
        val t = ScriptedTransport(appearAfterPolls = Int.MAX_VALUE)
        assertFailsWith<RelayTimeout> {
            RelayClient(
                t,
                "http://relay.test",
                "s",
                RelayClient.ROLE_INITIATOR,
                pollIntervalMillis = 1_000,
            ).fetch("commit")
        }
        assertEquals(60_000L, t.sleptMillis)
    }

    @Test
    fun aPeerThatJoinsAfterTheDefaultBoundIsStillFetchedUnderALongerOne() {
        // The on-phone case: the responder creates its key behind a fingerprint and joins
        // ~2 minutes after the invite was minted.
        val t = ScriptedTransport(appearAfterPolls = 120)
        val bytes = client(t, maxWaitMillis = 600_000).fetch("commit")
        assertEquals("peer", bytes.decodeToString())
        assertTrue(t.sleptMillis >= 120_000L, "waited ${t.sleptMillis}ms")
    }

    @Test
    fun theSamePeerIsATimeoutUnderTheDefaultBound() {
        val t = ScriptedTransport(appearAfterPolls = 120)
        assertFailsWith<RelayTimeout> { client(t, maxWaitMillis = RelayClient.DEFAULT_MAX_WAIT_MILLIS).fetch("commit") }
    }

    @Test
    fun theBoundIsHonouredExactly() {
        val t = ScriptedTransport(appearAfterPolls = Int.MAX_VALUE)
        assertFailsWith<RelayTimeout> { client(t, maxWaitMillis = 600_000).fetch("commit") }
        assertEquals(600_000L, t.sleptMillis)
    }
}
