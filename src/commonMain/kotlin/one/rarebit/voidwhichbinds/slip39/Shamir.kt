package one.rarebit.voidwhichbinds.slip39

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.SHA256

/** One share of one Shamir split: an x coordinate and, per secret byte, that byte's polynomial at x. */
internal class Point(val x: Int, val y: ByteArray)

/**
 * Shamir's secret sharing over GF(256), byte by byte, as SLIP-39 specifies it: the
 * shared secret is f(255) and its digest f(254), so neither is ever a share (share
 * indices are 0..15). Ported from void-which-binds-go `recovery/slip39/shamir.go`.
 */
internal object Shamir {
    const val SECRET_INDEX = 255
    const val DIGEST_INDEX = 254

    /** How much of HMAC-SHA256(R, S) the digest share carries. */
    const val DIGEST_BYTES = 4

    private const val BYTE_BITS = 8
    private const val BYTE_MASK = 0xff
    private const val HIGH_BIT_SHIFT = 7

    /** The Rijndael polynomial x⁸+x⁴+x³+x+1, less its x⁸ term. */
    private const val REDUCTION = 0x1b

    /** The exponent of the inverse: a²⁵⁴ = a⁻¹ in GF(256). */
    private const val INVERSE_EXPONENT = 254

    private val hmac = CryptographyProvider.Default.get(HMAC)

    /**
     * Multiply in GF(256). Written without tables or branches on the operands, so
     * its timing does not depend on the secret bytes it multiplies.
     */
    fun gfMul(a: Int, b: Int): Int {
        var p = 0
        var x = a
        var y = b
        repeat(BYTE_BITS) {
            p = p xor (x and -(y and 1))
            x = ((x shl 1) xor (REDUCTION and -(x ushr HIGH_BIT_SHIFT))) and BYTE_MASK
            y = y ushr 1
        }
        return p
    }

    /** The multiplicative inverse (gfInv(0) = 0). Only ever applied to public share indices. */
    fun gfInv(a: Int): Int {
        var r = 1
        var base = a
        var e = INVERSE_EXPONENT
        while (e > 0) {
            if (e and 1 == 1) r = gfMul(r, base)
            base = gfMul(base, base)
            e = e ushr 1
        }
        return r
    }

    /**
     * Evaluate at [x] the lowest-degree polynomial through [points], independently for
     * each byte position (Lagrange). The caller guarantees distinct x coordinates and
     * equal-length values.
     */
    fun interpolate(points: List<Point>, x: Int): ByteArray {
        val out = IntArray(points[0].y.size)
        for ((i, pi) in points.withIndex()) {
            var num = 1
            var den = 1
            for ((j, pj) in points.withIndex()) {
                if (j == i) continue
                // Subtraction in GF(2⁸) is XOR.
                num = gfMul(num, x xor pj.x)
                den = gfMul(den, pi.x xor pj.x)
            }
            val basis = gfMul(num, gfInv(den))
            for (k in out.indices) out[k] = out[k] xor gfMul(pi.y[k].toInt() and BYTE_MASK, basis)
        }
        return ByteArray(out.size) { out[it].toByte() }
    }

    /** The first [DIGEST_BYTES] of HMAC-SHA256(key = [r], message = [secret]). */
    private fun digest(r: ByteArray, secret: ByteArray): ByteArray = hmac
        .keyDecoder(SHA256)
        .decodeFromByteArrayBlocking(HMAC.Key.Format.RAW, r)
        .signatureGenerator()
        .generateSignatureBlocking(secret)
        .copyOf(DIGEST_BYTES)

    /**
     * The spec's SplitSecret(T, N, S): shares for x = 0..N-1 of a polynomial of degree
     * below T with S at x=255 and the digest at x=254. T-2 shares are random; with the
     * secret and the digest they fix the rest.
     */
    fun split(threshold: Int, count: Int, secret: ByteArray, random: (Int) -> ByteArray): List<ByteArray> {
        if (threshold !in 1..count || count > Slip39.MAX_SHARE_COUNT) {
            refuse(Slip39Error.INVALID_PARAMETERS, "$threshold-of-$count")
        }
        if (threshold == 1) return List(count) { secret.copyOf() }

        val shares = arrayOfNulls<ByteArray>(count)
        val base = ArrayList<Point>(threshold)
        for (i in 0 until threshold - 2) {
            val y = random(secret.size)
            shares[i] = y
            base += Point(i, y)
        }
        val r = random(secret.size - DIGEST_BYTES)
        base += Point(DIGEST_INDEX, digest(r, secret) + r)
        base += Point(SECRET_INDEX, secret)
        for (i in threshold - 2 until count) shares[i] = interpolate(base, i)
        return shares.map { it!! }
    }

    /**
     * The spec's RecoverSecret(T, points): the secret at x=255, checked against the
     * digest at x=254. The caller guarantees exactly T points with distinct x
     * coordinates and equal-length values.
     */
    fun recover(threshold: Int, points: List<Point>): ByteArray {
        if (threshold == 1) return points[0].y.copyOf()
        val secret = interpolate(points, SECRET_INDEX)
        val digest = interpolate(points, DIGEST_INDEX)
        val expected = digest(digest.copyOfRange(DIGEST_BYTES, digest.size), secret)
        if (!constantTimeEquals(expected, digest.copyOf(DIGEST_BYTES))) refuse(Slip39Error.DIGEST)
        return secret
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
