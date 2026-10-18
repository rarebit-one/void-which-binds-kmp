package one.rarebit.voidwhichbinds.custody

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [SealedDeviceKeys]'s unlock semantics, void-which-binds-go's CLI `lazyKeys` (#165), over the
 * Go `custody-sealedfile` blob. One real open runs Argon2id at the floor; the rest of the
 * opens go through a stand-in that checks the passphrase and builds the opened file from the
 * vector's seeds, so the semantics are tested without a 256 MiB derivation each.
 */
class SealedDeviceKeysTest {

    private val v: Map<String, Any> by lazy {
        val raw = javaClass.getResourceAsStream("/vectors/custody-sealedfile/device-floor.json")
            ?.readBytes()?.decodeToString() ?: error("vectors/custody-sealedfile/device-floor.json missing")
        MiniJson.parseObject(raw)
    }

    private val sealed: SealedFile by lazy { SealedFile.parse(Hex.decode(v["blob"] as String)) }
    private val pass: String by lazy { v["passphrase"] as String }

    @Suppress("UNCHECKED_CAST")
    private val seeds: Map<String, ByteArray> by lazy {
        (v["objects"] as List<Map<String, Any>>).associate { it["name"] as String to Hex.decode(it["seed"] as String) }
    }

    /** The plaintext layout: kind | name length | name | seed, per object. */
    private fun fakeOpen(p: ByteArray): SealedFile.Opened {
        if (!p.contentEquals(pass.encodeToByteArray())) throw SealedFile.SealedFileException.OpenFailed()
        val pt = sealed.objects.fold(ByteArray(0)) { acc, e ->
            val name = e.name.encodeToByteArray()
            acc + byteArrayOf(e.kind.byte, name.size.toByte()) + name + seeds.getValue(e.name)
        }
        return SealedFile.Opened(sealed, pt)
    }

    private var nanos = 0L
    private var asked = 0
    private var opens = 0

    /** Every opened file handed out, to check what was wiped. */
    private val held = mutableListOf<SealedFile.Opened>()

    /** The hold expiries scheduled (delay, action), run by hand. */
    private val expiries = mutableListOf<Pair<Long, () -> Unit>>()

    private fun keys(
        answer: () -> String,
        ttlMillis: Long = 1_000,
        given: MutableList<ByteArray> = mutableListOf(),
        slowKdfMillis: Long = 0,
    ) = SealedDeviceKeys(
        sealed,
        {
            asked++
            answer().encodeToByteArray().also(given::add)
        },
        ttlMillis,
        { nanos },
        {
            opens++
            advanceMillis(slowKdfMillis)
            fakeOpen(it).also(held::add)
        },
        { delay, action -> expiries += delay to action },
    )

    private fun SealedFile.Opened.isWiped() = runCatching { x25519Seed() }.isFailure

    private fun advanceMillis(ms: Long) {
        nanos += ms * 1_000_000
    }

    @Test
    fun aRealUnlockSignsAndUnwrapsWithTheSealedSeeds() {
        val k = SealedDeviceKeys(sealed, { pass.encodeToByteArray() })
        val msg = "desktop".encodeToByteArray()
        assertContentEquals(Ed25519Engine.sign(seeds.getValue("device"), msg), k.sign(msg))
        assertTrue(Ed25519Engine.verify(k.signPublicKey, msg, k.sign(msg)))
        val spaceKey = ByteArray(32) { it.toByte() }
        val wrapped = VoidbindEncryption.seal(spaceKey, k.encPublicKey)
        assertContentEquals(spaceKey, k.unwrap(wrapped))
        k.close()
        assertFalse(k.isUnlocked)
    }

    @Test
    fun publicHalvesNeverAsk() {
        val k = keys({ pass })
        assertEquals(sealed.signerId("device"), k.deviceId.render())
        val id = k.deviceIdentity()
        assertContentEquals(k.encPublicKey, id.encPublicKey)
        assertEquals(0, asked)
        id.sign("x".encodeToByteArray())
        assertEquals(1, asked)
        assertContentEquals(seeds.getValue(""), id.encPrivateKey)
        assertEquals(1, asked)
    }

    @Test
    fun oneUnlockServesTheHoldThenTheNextOperationUnlocksAgain() {
        val k = keys({ pass })
        k.sign(byteArrayOf(1))
        k.sign(byteArrayOf(2))
        advanceMillis(999)
        k.sign(byteArrayOf(3))
        assertEquals(1, asked)
        advanceMillis(1)
        assertFalse(k.isUnlocked)
        k.sign(byteArrayOf(4))
        assertEquals(2, asked)
    }

    @Test
    fun theHoldIsMeasuredFromWhenTheOpenReturns() {
        val k = keys({ pass }, slowKdfMillis = 5_000)
        k.sign(byteArrayOf(1))
        advanceMillis(999)
        k.sign(byteArrayOf(2))
        assertEquals(1, asked)
    }

    @Test
    fun theSeedsAreWipedWhenTheHoldLapsesNotAtTheNextOperation() {
        val k = keys({ pass })
        k.sign(byteArrayOf(1))
        val (delay, expire) = expiries.single()
        assertEquals(1_000, delay)
        advanceMillis(1_000)
        expire()
        assertTrue(held.single().isWiped())
        assertFalse(k.isUnlocked)
    }

    @Test
    fun aStaleExpiryLeavesALaterHoldAlone() {
        val k = keys({ pass })
        k.sign(byteArrayOf(1))
        advanceMillis(1_000)
        k.sign(byteArrayOf(2)) // re-unlocks: a new hold
        assertTrue(held[0].isWiped())
        expiries[0].second() // the first hold's expiry fires late
        assertFalse(held[1].isWiped())
        assertTrue(k.isUnlocked)
    }

    @Test
    fun aFailedFirstUnlockIsKept() {
        val k = keys({ "wrong" })
        assertFailsWith<SealedFile.SealedFileException.OpenFailed> { k.sign(byteArrayOf(1)) }
        assertFailsWith<SealedFile.SealedFileException.OpenFailed> { k.sign(byteArrayOf(1)) }
        assertEquals(1, asked)
        // An unlock screen's retry clears it.
        k.unlock(pass.encodeToByteArray())
        k.sign(byteArrayOf(1))
        assertEquals(1, asked)
    }

    @Test
    fun aDismissedFirstPromptIsKeptToo() {
        val k = keys({ throw IllegalStateException("dismissed") })
        assertFailsWith<IllegalStateException> { k.sign(byteArrayOf(1)) }
        assertFailsWith<IllegalStateException> { k.sign(byteArrayOf(1)) }
        assertEquals(1, asked)
        assertEquals(0, opens)
    }

    @Test
    fun aFailedRenewalIsNotKept() {
        var answer = pass
        val k = keys({ answer })
        k.sign(byteArrayOf(1))
        advanceMillis(1_000)
        answer = "wrong"
        assertFailsWith<SealedFile.SealedFileException.OpenFailed> { k.sign(byteArrayOf(2)) }
        answer = pass
        k.sign(byteArrayOf(3))
        assertEquals(3, asked)
    }

    @Test
    fun closeWipesTheHoldAndThePassphraseIsZeroed() {
        val given = mutableListOf<ByteArray>()
        val k = keys({ pass }, given = given)
        k.unlock()
        assertTrue(k.isUnlocked)
        k.close()
        assertFalse(k.isUnlocked)
        assertTrue(held.single().isWiped())
        assertTrue(given.single().all { it == 0.toByte() })
    }
}
