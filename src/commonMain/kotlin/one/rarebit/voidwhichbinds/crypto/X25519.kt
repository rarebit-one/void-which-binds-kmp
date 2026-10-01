package one.rarebit.voidwhichbinds.crypto

/**
 * X25519 (RFC 7748) — a faithful port of the TweetNaCl reference
 * `crypto_scalarmult`. Pure Kotlin, so it is byte-identical across JVM and
 * Kotlin/Native and matches Go's `crypto/ecdh` X25519 (and libsodium). The
 * scalar is clamped exactly as RFC 7748 / TweetNaCl require, so a raw 32-byte
 * seed behaves like Go's `ecdh.X25519().NewPrivateKey(seed)`.
 *
 * Verified against the RFC 7748 §5.2 test vector and, end-to-end, against a
 * live-voidbind-go seal KAT (a Go-sealed blob that this code must unwrap).
 */
internal object X25519 {

    private val _121665 = longArrayOf(0xDB41L, 1L).let { init ->
        LongArray(16).also {
            for (i in init.indices) {
                it[i] =
                    init[i]
            }
        }
    }

    private fun car25519(o: LongArray) {
        for (i in 0 until 16) {
            o[i] += (1L shl 16)
            val c = o[i] shr 16
            o[(i + 1) * (if (i < 15) 1 else 0)] += c - 1 + 37 * (c - 1) * (if (i == 15) 1L else 0L)
            o[i] -= c shl 16
        }
    }

    private fun sel25519(p: LongArray, q: LongArray, b: Int) {
        val c = (b - 1).toLong().inv()
        for (i in 0 until 16) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack25519(o: ByteArray, n: LongArray) {
        val m = LongArray(16)
        val t = n.copyOf()
        car25519(t)
        car25519(t)
        car25519(t)
        for (j in 0 until 2) {
            m[0] = t[0] - 0xffedL
            for (i in 1 until 15) {
                m[i] = t[i] - 0xffffL - ((m[i - 1] shr 16) and 1L)
                m[i - 1] = m[i - 1] and 0xffffL
            }
            m[15] = t[15] - 0x7fffL - ((m[14] shr 16) and 1L)
            val b = (m[15] shr 16) and 1L
            m[14] = m[14] and 0xffffL
            sel25519(t, m, (1L - b).toInt())
        }
        for (i in 0 until 16) {
            o[2 * i] = (t[i] and 0xffL).toByte()
            o[2 * i + 1] = (t[i] shr 8).toByte()
        }
    }

    private fun unpack25519(o: LongArray, n: ByteArray) {
        for (i in 0 until 16) o[i] = (n[2 * i].toLong() and 0xffL) + ((n[2 * i + 1].toLong() and 0xffL) shl 8)
        o[15] = o[15] and 0x7fffL
    }

    private fun add(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] + b[i]
    }
    private fun sub(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] - b[i]
    }

    private fun mul(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0 until 16) for (j in 0 until 16) t[i + j] += a[i] * b[j]
        for (i in 0 until 15) t[i] += 38 * t[i + 16]
        for (i in 0 until 16) o[i] = t[i]
        car25519(o)
        car25519(o)
    }

    private fun sqr(o: LongArray, a: LongArray) = mul(o, a, a)

    private fun inv25519(o: LongArray, i: LongArray) {
        val c = i.copyOf()
        for (a in 253 downTo 0) {
            sqr(c, c)
            if (a != 2 && a != 4) mul(c, c, i)
        }
        for (a in 0 until 16) o[a] = c[a]
    }

    /** X25519(scalar, point): the Montgomery ladder. scalar is clamped internally. */
    fun scalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        require(scalar.size == 32 && point.size == 32) { "x25519: scalar and point must be 32 bytes" }
        val z = ByteArray(32)
        for (i in 0 until 31) z[i] = scalar[i]
        z[31] = ((scalar[31].toInt() and 127) or 64).toByte()
        z[0] = (z[0].toInt() and 248).toByte()

        val x = LongArray(16)
        unpack25519(x, point)
        val a = LongArray(16)
        val b = LongArray(16)
        val c = LongArray(16)
        val d = LongArray(16)
        val e = LongArray(16)
        val f = LongArray(16)
        for (i in 0 until 16) b[i] = x[i]
        a[0] = 1
        d[0] = 1

        for (i in 254 downTo 0) {
            val r = (z[i shr 3].toInt() ushr (i and 7)) and 1
            sel25519(a, b, r)
            sel25519(c, d, r)
            add(e, a, c)
            sub(a, a, c)
            add(c, b, d)
            sub(b, b, d)
            sqr(d, e)
            sqr(f, a)
            mul(a, c, a)
            mul(c, b, e)
            add(e, a, c)
            sub(a, a, c)
            sqr(b, a)
            sub(c, d, f)
            mul(a, c, _121665)
            add(a, a, d)
            mul(c, c, a)
            mul(a, d, f)
            mul(d, b, x)
            sqr(b, e)
            sel25519(a, b, r)
            sel25519(c, d, r)
        }
        inv25519(c, c)
        mul(a, a, c)
        val q = ByteArray(32)
        pack25519(q, a)
        return q
    }

    private val BASE = ByteArray(32).also { it[0] = 9 }

    /** X25519(scalar, 9): the public key / base-point multiple of a scalar. */
    fun scalarMultBase(scalar: ByteArray): ByteArray = scalarMult(scalar, BASE)
}
