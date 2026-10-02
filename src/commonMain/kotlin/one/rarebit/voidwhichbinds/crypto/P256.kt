package one.rarebit.voidwhichbinds.crypto

/**
 * NIST P-256 public-point validation, pure Kotlin — the one check void-which-binds-go
 * makes through `crypto/ecdh.P256().NewPublicKey` on a `webauthn:es256:` member key
 * (ADR-0018, #116): 65 bytes, the SEC1 uncompressed prefix `0x04`, both coordinates
 * canonical field elements (`< p`), and the point on the curve
 * `y² = x³ − 3x + b (mod p)`. The point at infinity has no uncompressed encoding, so
 * an on-curve `(x, y)` is never the identity.
 *
 * Hand-rolled for the same reason as [X25519] and [Ed25519Group]: `commonMain` is
 * platform-free and cryptography-kotlin's EC key decoding does not promise an
 * on-curve check on every provider. Only PUBLIC data is handled (a member key named
 * in a signed op), so the arithmetic is a plain, variable-time double-and-add over
 * eight 32-bit limbs, chosen to be obviously correct rather than fast.
 */
internal object P256 {

    /** Length of a SEC1 uncompressed P-256 point: `0x04 ‖ X(32) ‖ Y(32)`. */
    const val UNCOMPRESSED_LEN = 65

    private const val LIMBS = 8
    private const val COORD_LEN = 32
    private const val UNCOMPRESSED_PREFIX: Byte = 0x04
    private const val LIMB_BITS = 32
    private const val LIMB_BYTES = 4
    private const val BYTE_BITS = 8
    private const val BYTE_MASK = 0xFFL
    private const val MASK32 = 0xFFFF_FFFFL

    private val P = fromHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
    private val B = fromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")

    /** Whether [raw] is a valid SEC1 uncompressed P-256 public point (on the curve). */
    fun isValidUncompressedPoint(raw: ByteArray): Boolean {
        if (raw.size != UNCOMPRESSED_LEN || raw[0] != UNCOMPRESSED_PREFIX) return false
        val x = fromBytes(raw, 1)
        val y = fromBytes(raw, 1 + COORD_LEN)
        return cmp(x, P) < 0 && cmp(y, P) < 0 && onCurve(x, y)
    }

    /** y² == x³ − 3x + b (mod p), for x, y < p. */
    private fun onCurve(x: LongArray, y: LongArray): Boolean {
        val lhs = mulMod(y, y)
        val x3 = mulMod(mulMod(x, x), x)
        val threeX = addMod(addMod(x, x), x)
        val rhs = addMod(subMod(x3, threeX), B)
        return cmp(lhs, rhs) == 0
    }

    // --- 256-bit unsigned integers: little-endian 32-bit limbs held in a LongArray ---

    private fun fromHex(hex: String): LongArray = fromBytes(Hex.decode(hex), 0)

    /** Big-endian 32 bytes at [off] → limbs. */
    private fun fromBytes(b: ByteArray, off: Int): LongArray {
        val out = LongArray(LIMBS)
        for (i in 0 until LIMBS) {
            var limb = 0L
            for (j in 0 until LIMB_BYTES) {
                limb = (limb shl BYTE_BITS) or (b[off + COORD_LEN - LIMB_BYTES * (i + 1) + j].toLong() and BYTE_MASK)
            }
            out[i] = limb
        }
        return out
    }

    private fun cmp(a: LongArray, b: LongArray): Int {
        for (i in LIMBS - 1 downTo 0) {
            if (a[i] != b[i]) return if (a[i] < b[i]) -1 else 1
        }
        return 0
    }

    /** a + b, returning the carry out of the top limb. */
    private fun add(out: LongArray, a: LongArray, b: LongArray): Long {
        var carry = 0L
        for (i in 0 until LIMBS) {
            val s = a[i] + b[i] + carry
            out[i] = s and MASK32
            carry = s ushr LIMB_BITS
        }
        return carry
    }

    /** a − b (mod 2^256), assuming the caller wants the wrapped difference. */
    private fun sub(out: LongArray, a: LongArray, b: LongArray) {
        var borrow = 0L
        for (i in 0 until LIMBS) {
            val d = a[i] - b[i] - borrow
            out[i] = d and MASK32
            borrow = if (d < 0) 1L else 0L
        }
    }

    /** (a + b) mod p, for a, b < p. */
    private fun addMod(a: LongArray, b: LongArray): LongArray {
        val s = LongArray(LIMBS)
        val carry = add(s, a, b)
        if (carry != 0L || cmp(s, P) >= 0) sub(s, s, P)
        return s
    }

    /** (a − b) mod p, for a, b < p. */
    private fun subMod(a: LongArray, b: LongArray): LongArray {
        val d = LongArray(LIMBS)
        if (cmp(a, b) >= 0) {
            sub(d, a, b)
        } else {
            sub(d, P, b)
            add(d, d, a) // p − b + a < p: no carry
        }
        return d
    }

    /** (a · b) mod p by double-and-add over b's bits, for a, b < p. */
    private fun mulMod(a: LongArray, b: LongArray): LongArray {
        var r = LongArray(LIMBS)
        for (i in LIMBS * LIMB_BITS - 1 downTo 0) {
            r = addMod(r, r)
            if ((b[i / LIMB_BITS] ushr (i % LIMB_BITS)) and 1L == 1L) r = addMod(r, a)
        }
        return r
    }
}
