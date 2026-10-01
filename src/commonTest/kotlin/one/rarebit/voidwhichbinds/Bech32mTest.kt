package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Bech32m
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class Bech32mTest {

    @Test
    fun recoverySecretRoundTrips() {
        val raw = ByteArray(Labels.RECOVERY_SECRET_LEN) { (it * 7 + 3).toByte() }
        val secret = RecoverySecret.of(raw)
        val encoded = secret.format()

        assertTrue(encoded.startsWith(Labels.RECOVERY_HRP + "1"), "HRP prefix: $encoded")

        val parsed = RecoverySecret.parse(encoded)
        assertTrue(parsed.bytes.contentEquals(raw), "round-trip bytes must match")
        assertEquals(secret, parsed)
        assertEquals(encoded, parsed.format())
    }

    @Test
    fun bech32mChecksumIsRejectedWhenCorrupted() {
        val secret = RecoverySecret.of(ByteArray(32) { 0x11 })
        val encoded = secret.format()
        // Flip one data character (last char before... just mutate a middle char).
        val idx = encoded.length / 2
        val other = if (encoded[idx] == 'q') 'p' else 'q'
        val corrupted = encoded.substring(0, idx) + other + encoded.substring(idx + 1)
        assertFailsWith<IllegalArgumentException> { RecoverySecret.parse(corrupted) }
    }

    @Test
    fun wrongHrpRejected() {
        // A well-formed bech32m string under a different HRP must not parse as recovery.
        val fiveBit = Bech32m.convertBits(Bech32m.bytesToInts(ByteArray(32) { 1 }), 8, 5, pad = true)
        val notHeyarr = Bech32m.encode("void", fiveBit)
        assertFailsWith<IllegalArgumentException> { RecoverySecret.parse(notHeyarr) }
    }

    @Test
    fun convertBitsRoundTrips() {
        val bytes = ByteArray(20) { (it * 31 + 5).toByte() }
        val five = Bech32m.convertBits(Bech32m.bytesToInts(bytes), 8, 5, pad = true)
        val back = Bech32m.intsToBytes(Bech32m.convertBits(five, 5, 8, pad = false))
        assertTrue(bytes.contentEquals(back))
    }
}
