package one.rarebit.voidwhichbinds.crypto

/**
 * XChaCha20-Poly1305 (24-byte nonce), byte-identical to Go's
 * `golang.org/x/crypto/chacha20poly1305.NewX` and libsodium's
 * `crypto_aead_xchacha20poly1305_ietf`.
 *
 * The crypto provider (cryptography-kotlin) supplies the **IETF** ChaCha20-Poly1305
 * AEAD (12-byte nonce, RFC 8439) with an explicit IV. XChaCha20 is the standard
 * extension void-which-binds-go's `encryption` package uses: derive a subkey with
 * **HChaCha20** over the key and the first 16 nonce bytes, then run IETF
 * ChaCha20-Poly1305 under that subkey with the 12-byte nonce
 * `0x00000000 || nonce[16:24]`.
 *
 * The ONLY hand-written primitive is HChaCha20 — a keyless permutation (the ChaCha
 * double round with no final feed-forward add), the safe, standard way libsodium
 * and the CFRG draft build XChaCha20. The AEAD, its ChaCha20 keystream and the
 * Poly1305 tag stay in the vetted provider. Pinned by RFC vectors + a live
 * void-which-binds-go KAT.
 */
internal object XChaCha20Poly1305 {
    const val KEY_SIZE = 32
    const val NONCE_SIZE = 24
    const val TAG_SIZE = 16

    /** AEAD-seal [plaintext] → ciphertext‖tag (Go's `AEAD.Seal` framing). */
    fun encrypt(key: ByteArray, nonce24: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val (subkey, ietfNonce) = derive(key, nonce24)
        return aeadIetfSeal(subkey, ietfNonce, aad, plaintext)
    }

    /** AEAD-open ciphertext‖tag; throws on an authentication failure. */
    fun decrypt(key: ByteArray, nonce24: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val (subkey, ietfNonce) = derive(key, nonce24)
        return aeadIetfOpen(subkey, ietfNonce, aad, ciphertext)
    }

    /** The XChaCha20 subkey + the reduced 12-byte IETF nonce for [key]/[nonce24]. */
    private fun derive(key: ByteArray, nonce24: ByteArray): Pair<ByteArray, ByteArray> {
        require(key.size == KEY_SIZE) { "xchacha: key must be $KEY_SIZE bytes, got ${key.size}" }
        require(nonce24.size == NONCE_SIZE) { "xchacha: nonce must be $NONCE_SIZE bytes, got ${nonce24.size}" }
        val subkey = hChaCha20(key, nonce24.copyOfRange(0, 16))
        val ietfNonce = ByteArray(12) // first 4 bytes zero; last 8 = nonce[16:24]
        nonce24.copyInto(ietfNonce, destinationOffset = 4, startIndex = 16, endIndex = 24)
        return subkey to ietfNonce
    }

    // ChaCha20 constants: "expand 32-byte k".
    private const val C0 = 0x61707865
    private const val C1 = 0x3320646e
    private const val C2 = 0x79622d32
    private const val C3 = 0x6b206574

    /**
     * HChaCha20: 20 rounds of the ChaCha permutation over a state built from the
     * key and a 16-byte nonce, returning words 0..3 ‖ 12..15 — the RFC-draft
     * intermediate-key derivation, with **no** final add of the initial state.
     */
    private fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        val s = IntArray(16)
        s[0] = C0
        s[1] = C1
        s[2] = C2
        s[3] = C3
        for (i in 0 until 8) s[4 + i] = leU32(key, i * 4)
        for (i in 0 until 4) s[12 + i] = leU32(nonce16, i * 4)
        repeat(10) {
            quarterRound(s, 0, 4, 8, 12)
            quarterRound(s, 1, 5, 9, 13)
            quarterRound(s, 2, 6, 10, 14)
            quarterRound(s, 3, 7, 11, 15)
            quarterRound(s, 0, 5, 10, 15)
            quarterRound(s, 1, 6, 11, 12)
            quarterRound(s, 2, 7, 8, 13)
            quarterRound(s, 3, 4, 9, 14)
        }
        val out = ByteArray(32)
        putLeU32(s[0], out, 0)
        putLeU32(s[1], out, 4)
        putLeU32(s[2], out, 8)
        putLeU32(s[3], out, 12)
        putLeU32(s[12], out, 16)
        putLeU32(s[13], out, 20)
        putLeU32(s[14], out, 24)
        putLeU32(s[15], out, 28)
        return out
    }

    private fun quarterRound(s: IntArray, a: Int, b: Int, c: Int, d: Int) {
        s[a] += s[b]
        s[d] = (s[d] xor s[a]).rotateLeft(16)
        s[c] += s[d]
        s[b] = (s[b] xor s[c]).rotateLeft(12)
        s[a] += s[b]
        s[d] = (s[d] xor s[a]).rotateLeft(8)
        s[c] += s[d]
        s[b] = (s[b] xor s[c]).rotateLeft(7)
    }

    private fun leU32(b: ByteArray, off: Int): Int = (b[off].toInt() and 0xff) or
        ((b[off + 1].toInt() and 0xff) shl 8) or
        ((b[off + 2].toInt() and 0xff) shl 16) or
        ((b[off + 3].toInt() and 0xff) shl 24)

    private fun putLeU32(v: Int, out: ByteArray, off: Int) {
        out[off] = (v and 0xff).toByte()
        out[off + 1] = ((v ushr 8) and 0xff).toByte()
        out[off + 2] = ((v ushr 16) and 0xff).toByte()
        out[off + 3] = ((v ushr 24) and 0xff).toByte()
    }
}
