package one.rarebit.voidwhichbinds.slip39

/**
 * Why [Slip39.split] or [Slip39.combine] refused. One value per sentinel error of
 * void-which-binds-go `recovery/slip39` (`ErrChecksum` is [CHECKSUM], and so on), with the
 * same base message, so a refusal reads the same on both sides.
 */
enum class Slip39Error(val message: String) {
    /**
     * A split the spec forbids: a threshold out of range, more than 16 groups or
     * members, a member threshold of 1 in a group of more than one, or an iteration
     * exponent over 15.
     */
    INVALID_PARAMETERS("slip39: invalid sharing parameters"),

    /** A master secret shorter than 128 bits or not a whole number of 16-bit units. */
    SECRET_LENGTH("slip39: master secret must be at least 16 bytes and an even number of bytes"),

    /** A passphrase with a character outside printable ASCII (32 to 126). */
    PASSPHRASE("slip39: passphrase must be printable ASCII"),

    /** A mnemonic containing a word that is not in the SLIP-39 wordlist. */
    UNKNOWN_WORD("slip39: unknown word"),

    /** A mnemonic with fewer than 20 words, or a word count that cannot hold a whole secret. */
    INVALID_LENGTH("slip39: invalid mnemonic length"),

    /** A mnemonic whose RS1024 checksum does not verify: a transcription error. */
    CHECKSUM("slip39: mnemonic checksum does not verify"),

    /** A mnemonic whose share value is padded with non-zero bits. */
    PADDING("slip39: invalid mnemonic padding"),

    /** A mnemonic whose checksum verifies but whose metadata is impossible. */
    MALFORMED_SHARE("slip39: malformed share"),

    /** Mnemonics that are not from the same split: their random identifiers differ. */
    IDENTIFIER_MISMATCH("slip39: mnemonics are from different backups (identifiers differ)"),

    /**
     * Mnemonics with the same identifier that disagree on anything else every share
     * of one split agrees on (extendable flag, iteration exponent, group threshold
     * and count, length, or within a group the member threshold).
     */
    PARAMETER_MISMATCH("slip39: mnemonics disagree on their sharing parameters"),

    /** Two mnemonics with the same member index in the same group, such as one share given twice. */
    DUPLICATE_INDEX("slip39: duplicate share index"),

    /** Fewer groups than the group threshold, or fewer members of a group than its threshold. */
    INSUFFICIENT_SHARES("slip39: not enough shares"),

    /**
     * More groups than the group threshold, or more members of a group than its
     * threshold. The spec requires exactly the threshold, so no share goes unchecked
     * by the digest.
     */
    TOO_MANY_SHARES("slip39: more shares than the threshold"),

    /** Shares that pass every other check but do not reconstruct a secret matching its digest. */
    DIGEST("slip39: shares do not reconstruct a secret that matches its digest"),
}

/**
 * A typed SLIP-39 refusal: [error] says why (compare it, as Go compares with
 * `errors.Is`), [detail] adds the specifics, and [mnemonicIndex] (from 0) names
 * the mnemonic at fault when the refusal is about one of them rather than the set,
 * mirroring void-which-binds-go's `*slip39.MnemonicError`. The message reads like Go's:
 * `slip39: mnemonic checksum does not verify (mnemonic 2)`, counting from 1.
 *
 * An [IllegalArgumentException], so it crosses to Swift as a catchable error where
 * a caller declares it, and reads as bad input everywhere else.
 */
class Slip39Exception(val error: Slip39Error, val detail: String? = null, val mnemonicIndex: Int? = null) :
    IllegalArgumentException(render(error, detail, mnemonicIndex)) {

    /** The same refusal, attributed to the mnemonic at [index]. */
    internal fun at(index: Int): Slip39Exception = Slip39Exception(error, detail, index)

    private companion object {
        fun render(error: Slip39Error, detail: String?, mnemonicIndex: Int?): String {
            val base = if (detail == null) error.message else "${error.message}: $detail"
            return if (mnemonicIndex == null) base else "$base (mnemonic ${mnemonicIndex + 1})"
        }
    }
}

/** Throw a [Slip39Exception]: one call site per refusal, so no function counts its throws. */
internal fun refuse(error: Slip39Error, detail: String? = null): Nothing = throw Slip39Exception(error, detail)
