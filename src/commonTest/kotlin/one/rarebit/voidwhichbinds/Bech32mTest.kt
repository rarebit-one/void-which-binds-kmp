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
        val foreign = Bech32m.encode("void", fiveBit)
        val e = assertFailsWith<IllegalArgumentException> { RecoverySecret.parse(foreign) }
        assertTrue(e !is RecoverySecret.GenerationRetiredException, "a foreign HRP is malformed, not retired")
    }

    /**
     * void-which-binds-go `TestParseRefusesGen1` (ADR-0022): a gen1 secret (`heyarr1…`, the
     * gen1 rendering of the counting-entropy known answer) is refused as retired in
     * every form a person might type or scan it, a truncated one included, and the
     * retired refusal is distinct from a malformed or mistyped secret.
     */
    @Test
    fun aGen1SecretIsRefusedAsRetired() {
        val gen1 = "heyarr1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6e0ucu"
        for (input in listOf(gen1, gen1.uppercase(), "heya rr1q qqsy qcyq 5rqw")) {
            assertFailsWith<RecoverySecret.GenerationRetiredException>(input) { RecoverySecret.parse(input) }
            assertFailsWith<RecoverySecret.GenerationRetiredException>(input) { UserIdentity.restore(input) }
        }
        // The same entropy under the gen2 HRP parses.
        val gen2 = RecoverySecret.of(ByteArray(32) { it.toByte() }).format()
        assertEquals("void-which-binds1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0stska6c", gen2)
        assertEquals(75, gen2.length)
    }

    @Test
    fun hrpOfReadsStructureWithoutTheChecksum() {
        assertEquals("heyarr", Bech32m.hrpOf("heyarr1qqqsyqcy"))
        assertEquals("void-which-binds", Bech32m.hrpOf("VOID-WHICH-BINDS1QQQSYQCY"))
        assertEquals(null, Bech32m.hrpOf("Heyarr1qqqsyqcy")) // mixed case
        assertEquals(null, Bech32m.hrpOf("heyarr1qqqb")) // 'b' is not in the alphabet, and too short
        assertEquals(null, Bech32m.hrpOf("1qqqqqqqq")) // empty prefix
    }

    @Test
    fun convertBitsRoundTrips() {
        val bytes = ByteArray(20) { (it * 31 + 5).toByte() }
        val five = Bech32m.convertBits(Bech32m.bytesToInts(bytes), 8, 5, pad = true)
        val back = Bech32m.intsToBytes(Bech32m.convertBits(five, 5, 8, pad = false))
        assertTrue(bytes.contentEquals(back))
    }
}
