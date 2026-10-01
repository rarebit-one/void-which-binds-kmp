package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Bech32m

/**
 * The 256-bit account recovery secret, rendered as a bech32m string with HRP
 * [Labels.RECOVERY_HRP] (`heyarr`) — the same human-facing format as void-which-binds-go.
 *
 * The raw 32 bytes seed HKDF (label [Labels.HKDF_USER_IDENTITY_ED25519_SEED]) to
 * re-derive the user identity Ed25519 key on a fresh device; that derivation is
 * an [expect] crypto op and lives outside this pure model.
 */
class RecoverySecret private constructor(val bytes: ByteArray) {

    init {
        require(bytes.size == Labels.RECOVERY_SECRET_LEN) {
            "recovery secret must be ${Labels.RECOVERY_SECRET_LEN} bytes, got ${bytes.size}"
        }
    }

    /** Render as a bech32m string, e.g. `heyarr1...`. */
    fun format(): String {
        val fiveBit = Bech32m.convertBits(Bech32m.bytesToInts(bytes), 8, 5, pad = true)
        return Bech32m.encode(Labels.RECOVERY_HRP, fiveBit)
    }

    override fun toString(): String = format()

    /**
     * Split this secret into [count] SLIP-39 shares, any [threshold] of which rebuild
     * it, per the voidbind profile ([RecoveryShares.split]; void-which-binds-go
     * `recovery.SplitShares`). Splitting revokes nothing: this secret still works.
     */
    @Throws(IllegalArgumentException::class)
    fun splitShares(
        threshold: Int = RecoveryShares.DEFAULT_THRESHOLD,
        count: Int = RecoveryShares.DEFAULT_COUNT,
        passphrase: String = "",
    ): List<String> = RecoveryShares.split(this, threshold, count, passphrase)

    override fun equals(other: Any?): Boolean = other is RecoverySecret && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    companion object {
        /** Wrap raw 32 bytes (e.g. freshly generated CSPRNG output). */
        fun of(bytes: ByteArray): RecoverySecret = RecoverySecret(bytes.copyOf())

        /**
         * Parse a bech32m recovery string. Enforces the `heyarr` HRP and 32-byte length.
         *
         * Whitespace anywhere is ignored, so the grouped form the secret is displayed
         * and written down in (`heya rr1q …`, possibly across lines) parses as typed,
         * and so does the all-uppercase form a QR code carries. Neither can change
         * which secret is read: whitespace is not in the bech32 alphabet, and case is
         * folded before the checksum (mixed case is still refused). Mirrors
         * void-which-binds-go `recovery.ParseSecret`.
         */
        fun parse(s: String): RecoverySecret {
            val decoded = Bech32m.decode(s.filterNot { it.isWhitespace() })
            require(decoded.hrp == Labels.RECOVERY_HRP) {
                "wrong HRP: expected '${Labels.RECOVERY_HRP}', got '${decoded.hrp}'"
            }
            val bytes = Bech32m.intsToBytes(Bech32m.convertBits(decoded.data, 5, 8, pad = false))
            return RecoverySecret(bytes)
        }

        /**
         * Rebuild a secret from SLIP-39 share [mnemonics] ([RecoveryShares.combine];
         * void-which-binds-go `recovery.CombineShares`). A bad share, a mixed set or the wrong
         * number of shares is a typed [one.rarebit.voidwhichbinds.slip39.Slip39Exception];
         * shares holding anything but 32 bytes are a [NotARecoverySecretException].
         */
        @Throws(IllegalArgumentException::class)
        fun fromShares(mnemonics: List<String>, passphrase: String = ""): RecoverySecret {
            val secret = RecoveryShares.combine(mnemonics, passphrase)
            return secret
        }
    }
}
