package one.rarebit.voidwhichbinds.slip39

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.PBKDF2
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The SLIP-39 building blocks, on every target (so the iOS provider is held to the
 * same answers as the JDK's): the pinned wordlist, the provider's PBKDF2, GF(256)
 * and the Feistel cipher.
 */
class Slip39PrimitivesTest {

    /** The SHA-256 of void-which-binds-go's `recovery/slip39/wordlist.txt`, one word per line. */
    private val wordlistSha256 = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"

    @Test
    fun theWordlistIsPinned() {
        val file = Slip39Wordlist.words.joinToString("\n", postfix = "\n")
        val sum = CryptographyProvider.Default.get(SHA256).hasher().hashBlocking(file.encodeToByteArray())
        assertEquals(wordlistSha256, Hex.encode(sum), "the SLIP-39 wordlist changed")
        val words = Slip39Wordlist.words
        assertEquals(Slip39Wordlist.SIZE, words.size)
        assertEquals(words.sorted(), words, "the wordlist is sorted")
        assertEquals(words.size, words.map { it.take(4) }.toSet().size, "every four-letter prefix is unique")
        assertEquals(0, Slip39Wordlist.indexOf("academic"))
        assertEquals(Slip39Wordlist.SIZE - 1, Slip39Wordlist.indexOf("zero"))
    }

    private fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): String = Hex.encode(
        CryptographyProvider.Default.get(PBKDF2)
            .secretDerivation(digest = SHA256, iterations = iterations, outputSize = length.bytes, salt = salt)
            .deriveSecretToByteArrayBlocking(password),
    )

    /**
     * The provider's PBKDF2-HMAC-SHA256 against RFC 7914 §11's known answers, plus the
     * shape SLIP-39 feeds it: a password that starts with the round byte 0x00 (which a
     * char-based password API must carry through unchanged). That answer is Python's
     * `hashlib.pbkdf2_hmac('sha256', b'\x00TREZOR', b'shamir\x12\x34' + bytes(range(16)), 2500, 16)`.
     */
    @Test
    fun pbkdf2MatchesKnownAnswers() {
        assertEquals(
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            pbkdf2("passwd".encodeToByteArray(), "salt".encodeToByteArray(), 1, 64),
        )
        assertEquals(
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56" +
                "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            pbkdf2("Password".encodeToByteArray(), "NaCl".encodeToByteArray(), 80000, 64),
        )
        val salt = "shamir".encodeToByteArray() + byteArrayOf(0x12, 0x34) + ByteArray(16) { it.toByte() }
        assertEquals(
            "16566636da4ffcc8e736b0fc78123b77",
            pbkdf2(byteArrayOf(0) + "TREZOR".encodeToByteArray(), salt, 2500, 16),
        )
        assertEquals(
            "5b1ebf080c6047aacffbc36de2578806",
            pbkdf2(byteArrayOf(3), ByteArray(16) { it.toByte() }, 5000, 16),
        )
    }

    /** GF(256) against a table-free reference, every inverse, and FIPS-197 §4.2's 0x53·0xCA = 1. */
    @Test
    fun gf256() {
        fun reference(a: Int, b: Int): Int {
            var p = 0
            var x = a
            var y = b
            while (y != 0) {
                if (y and 1 != 0) p = p xor x
                x = x shl 1
                if (x and 0x100 != 0) x = x xor 0x11b
                y = y ushr 1
            }
            return p
        }
        for (a in 0..255) {
            for (b in 0..255) assertEquals(reference(a, b), Shamir.gfMul(a, b), "gfMul($a, $b)")
            if (a != 0) assertEquals(1, Shamir.gfMul(a, Shamir.gfInv(a)), "gfInv($a)")
        }
        assertEquals(1, Shamir.gfMul(0x53, 0xca))
    }

    @Test
    fun feistelInverts() {
        val secret = "0123456789abcdef0123456789abcdef".encodeToByteArray()
        for (extendable in listOf(false, true)) {
            val params = SplitParams(0x1234, extendable, 0, 1, 1)
            val encrypted = Feistel.encrypt(secret, "TREZOR".encodeToByteArray(), params)
            assertFalse(encrypted.contentEquals(secret), "encryption is the identity")
            assertContentEquals(secret, Feistel.decrypt(encrypted, "TREZOR".encodeToByteArray(), params))
        }
    }

    /** Share values of every length a secret can have round-trip through the 10-bit words. */
    @Test
    fun shareValuesRoundTrip() {
        for (size in listOf(16, 18, 20, 30, 32, 64)) {
            val value = ByteArray(size) { (it * 37 + 11).toByte() }
            val words = Share.valueToWords(value)
            assertTrue(words.all { it in 0 until Slip39Wordlist.SIZE })
            assertContentEquals(value, Share.wordsToValue(words), "$size bytes")
        }
    }
}
