package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Bech32m
import one.rarebit.voidwhichbinds.crypto.GoStrings

/**
 * The 256-bit account recovery secret, rendered as a bech32m string with HRP
 * [Labels.RECOVERY_HRP] (`void-which-binds`) — the same human-facing format as void-which-binds-go.
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

    /** Render as a bech32m string, e.g. `void-which-binds1...`. */
    fun format(): String {
        val fiveBit = Bech32m.convertBits(Bech32m.bytesToInts(bytes), 8, 5, pad = true)
        return Bech32m.encode(Labels.RECOVERY_HRP, fiveBit)
    }

    override fun toString(): String = format()

    /**
     * Split this secret into [count] SLIP-39 shares, any [threshold] of which rebuild
     * it, per the Void-Which-Binds SLIP-39 profile ([RecoveryShares.split]; void-which-binds-go
     * `recovery.SplitShares`). Splitting revokes nothing: this secret still works.
     */
    @Throws(IllegalArgumentException::class)
    fun splitShares(
        threshold: Int = RecoveryShares.DEFAULT_THRESHOLD,
        count: Int = RecoveryShares.DEFAULT_COUNT,
        passphrase: String = "",
    ): List<String> = RecoveryShares.split(this, threshold, count, passphrase)

    /**
     * A generation-1 recovery secret (`heyarr1…`). gen1 is retired (void-which-binds-go
     * ADR-0022): its secret derives keys under the gen1 labels, which no verifier
     * accepts, so it is refused rather than read. Mirrors Go's
     * `recovery.ErrGenerationRetired`; it is an [IllegalArgumentException] like every
     * other parse refusal, but a distinct type so a caller can name the old sheet.
     */
    class GenerationRetiredException :
        IllegalArgumentException(
            "recovery: this is a retired generation-1 (heyarr1…) recovery secret; " +
                "gen1 is not readable by gen2 (void-which-binds-go ADR-0022)",
        )

    override fun equals(other: Any?): Boolean = other is RecoverySecret && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    companion object {
        /** The generation-1 HRP, recognised only to refuse it (Go's `retiredHRP`). */
        private const val RETIRED_HRP = "heyarr"

        /** Wrap raw 32 bytes (e.g. freshly generated CSPRNG output). */
        fun of(bytes: ByteArray): RecoverySecret = RecoverySecret(bytes.copyOf())

        /**
         * Parse a bech32m recovery string. Enforces the `void-which-binds` HRP and 32-byte length.
         *
         * A retired generation-1 secret (`heyarr1…`, void-which-binds-go ADR-0022) is
         * refused with [GenerationRetiredException], whatever the rest of it holds,
         * before the checksum is consulted (Go's `recovery.ErrGenerationRetired`). It is
         * deliberately distinct from a malformed or mistyped secret, so a caller can say
         * "this is the old sheet" rather than "you mistyped it".
         *
         * Whitespace (Go's `unicode.IsSpace`: U+0085 is, U+001C..U+001F are not) anywhere is
         * ignored, so the grouped form the secret is displayed
         * and written down in (`void -whi ch-b inds 1q…`, possibly across lines) parses as typed,
         * and so does the all-uppercase form a QR code carries. Neither can change
         * which secret is read: whitespace is not in the bech32 alphabet, and case is
         * folded before the checksum (mixed case is still refused). Mirrors
         * void-which-binds-go `recovery.ParseSecret`.
         */
        fun parse(s: String): RecoverySecret {
            // Go's strings.Fields set (unicode.IsSpace), not Kotlin's isWhitespace (#107).
            val compact = s.filterNot(GoStrings::isSpace)
            if (Bech32m.hrpOf(compact) == RETIRED_HRP) throw GenerationRetiredException()
            val decoded = Bech32m.decode(compact)
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
