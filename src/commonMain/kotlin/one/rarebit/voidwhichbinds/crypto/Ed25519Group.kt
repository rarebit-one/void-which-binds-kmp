package one.rarebit.voidwhichbinds.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA512

/**
 * Ed25519 public-key derivation FROM a raw 32-byte seed — a faithful port of the
 * TweetNaCl reference (`crypto_sign_keypair`'s public half), pure Kotlin so it is
 * byte-identical across JVM, Android and Apple and matches Go's
 * `ed25519.NewKeyFromSeed(seed).Public()`.
 *
 * ## Why this is hand-rolled
 *
 * Neither the JDK EdDSA provider nor Apple's derives the public key FROM a private
 * seed — the JDK throws *"Getting public key from private key for EdDSA is not
 * supported ... without BouncyCastle"*. But a recovery-secret-derived identity
 * ([one.rarebit.voidwhichbinds.UserIdentity]) starts from ONLY a seed (the HKDF output)
 * and MUST recover the EXACT public key peers pinned at enrolment (ADR-0048) —
 * otherwise recovery reconstructs a different, useless identity. So this one
 * derivation is hand-rolled, exactly as [X25519] is and for the same reason;
 * signing itself stays on the vetted provider ([one.rarebit.voidwhichbinds.Ed25519Engine]).
 *
 * The scalar clamp and the point encoding are RFC 8032 §5.1.5 verbatim, and the
 * field arithmetic mirrors [X25519]'s TweetNaCl port. Proven against a
 * live-voidbind-go KAT: recovery secret → HKDF seed → this public key.
 */
internal object Ed25519Group {

    private val sha512 = CryptographyProvider.Default.get(SHA512).hasher()

    /** The RAW 32-byte Ed25519 public key for a RAW 32-byte private [seed]. */
    fun publicKeyFromSeed(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "ed25519: seed must be 32 bytes" }
        // RFC 8032: h = SHA-512(seed); the low 32 bytes, clamped, are the scalar.
        val h = sha512.hashBlocking(seed)
        h[0] = (h[0].toInt() and 248).toByte()
        h[31] = ((h[31].toInt() and 127) or 64).toByte()
        val p = Array(4) { LongArray(16) }
        scalarBase(p, h) // uses h[0..31]
        val pk = ByteArray(32)
        pack(pk, p)
        return pk
    }

    // --- Field element (gf): 16 limbs, radix 2^16, TweetNaCl layout over 2^255-19 ---

    private fun gf(vararg init: Int): LongArray =
        LongArray(16).also { for (i in init.indices) it[i] = init[i].toLong() }

    private val gf1 = gf(1)
    private val D2 = gf(
        0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
        0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
    )
    private val X = gf(
        0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
    )
    private val Y = gf(
        0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    )

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

    private fun inv25519(o: LongArray, i: LongArray) {
        val c = i.copyOf()
        for (a in 253 downTo 0) {
            sqr(c, c)
            if (a != 2 && a != 4) mul(c, c, i)
        }
        for (a in 0 until 16) o[a] = c[a]
    }

    private fun sqr(o: LongArray, a: LongArray) = mul(o, a, a)

    private fun par25519(a: LongArray): Int {
        val d = ByteArray(32)
        pack25519(d, a)
        return d[0].toInt() and 1
    }

    // --- Twisted-Edwards point ops on extended coordinates (X, Y, Z, T) ---

    /** p += q (TweetNaCl `add`). Safe when q === p: all reads of p precede writes. */
    private fun edAdd(p: Array<LongArray>, q: Array<LongArray>) {
        val a = LongArray(16)
        val b = LongArray(16)
        val c = LongArray(16)
        val d = LongArray(16)
        val t = LongArray(16)
        val e = LongArray(16)
        val f = LongArray(16)
        val g = LongArray(16)
        val h = LongArray(16)
        sub(a, p[1], p[0])
        sub(t, q[1], q[0])
        mul(a, a, t)
        add(b, p[0], p[1])
        add(t, q[0], q[1])
        mul(b, b, t)
        mul(c, p[3], q[3])
        mul(c, c, D2)
        mul(d, p[2], q[2])
        add(d, d, d)
        sub(e, b, a)
        sub(f, d, c)
        add(g, d, c)
        add(h, b, a)
        mul(p[0], e, f)
        mul(p[1], h, g)
        mul(p[2], g, f)
        mul(p[3], e, h)
    }

    private fun cswap(p: Array<LongArray>, q: Array<LongArray>, b: Int) {
        for (i in 0 until 4) sel25519(p[i], q[i], b)
    }

    private fun scalarMult(p: Array<LongArray>, q: Array<LongArray>, s: ByteArray) {
        // p := identity (0, 1, 1, 0)
        for (i in 0 until 16) {
            p[0][i] = 0
            p[1][i] = gf1[i]
            p[2][i] = gf1[i]
            p[3][i] = 0
        }
        for (i in 255 downTo 0) {
            val bit = ((s[i ushr 3].toInt() ushr (i and 7)) and 1)
            cswap(p, q, bit)
            edAdd(q, p)
            edAdd(p, p)
            cswap(p, q, bit)
        }
    }

    private fun scalarBase(p: Array<LongArray>, s: ByteArray) {
        val q = Array(4) { LongArray(16) }
        for (i in 0 until 16) {
            q[0][i] = X[i]
            q[1][i] = Y[i]
            q[2][i] = gf1[i]
        }
        mul(q[3], X, Y)
        scalarMult(p, q, s)
    }

    private fun pack(r: ByteArray, p: Array<LongArray>) {
        val zi = LongArray(16)
        inv25519(zi, p[2])
        val tx = LongArray(16)
        val ty = LongArray(16)
        mul(tx, p[0], zi)
        mul(ty, p[1], zi)
        pack25519(r, ty)
        r[31] = (r[31].toInt() xor (par25519(tx) shl 7)).toByte()
    }
}
