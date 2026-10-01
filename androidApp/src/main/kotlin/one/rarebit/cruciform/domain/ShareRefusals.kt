package one.rarebit.cruciform.domain

import one.rarebit.voidwhichbinds.NotARecoverySecretException
import one.rarebit.voidwhichbinds.slip39.Slip39Error
import one.rarebit.voidwhichbinds.slip39.Slip39Exception

/**
 * What to tell a person whose recovery share was refused (void-which-binds-go ADR-0011): which
 * share, counting from 1 in the order they were entered, and what to do about it. The
 * library's typed refusal decides the words; its raw text is never shown.
 */
internal object ShareRefusals {

    fun describe(e: IllegalArgumentException): String = when (e) {
        is NotARecoverySecretException -> NOT_A_RECOVERY_SECRET
        is Slip39Exception -> describe(e)
        else -> GENERIC
    }

    private fun describe(e: Slip39Exception): String {
        val share = e.mnemonicIndex?.let { "Share ${it + 1}" } ?: "These shares"
        return when (e.error) {
            Slip39Error.CHECKSUM ->
                "$share has a mistake: a word is wrong, missing or out of order. " +
                    "Check it against the paper, word by word."

            Slip39Error.UNKNOWN_WORD ->
                "$share has a word that isn't a share word (${e.detail}). Check its spelling against the paper."

            Slip39Error.INVALID_LENGTH ->
                "$share has the wrong number of words. A recovery share is $SHARE_WORDS words long."

            Slip39Error.IDENTIFIER_MISMATCH ->
                "$share is from a different set of shares than share 1. Each split makes its own set, " +
                    "and shares from different sets can't be mixed."

            Slip39Error.PARAMETER_MISMATCH ->
                "$share doesn't match share 1's settings, so they aren't from the same set."

            Slip39Error.DUPLICATE_INDEX -> "$share is one you've already entered. Enter a different share."

            Slip39Error.DIGEST ->
                "These shares don't rebuild a consistent secret, so one of them is wrong. " +
                    "Start over and check each share against its paper."

            Slip39Error.INSUFFICIENT_SHARES, Slip39Error.TOO_MANY_SHARES ->
                "That isn't the number of shares this set needs. Start over."

            Slip39Error.PADDING, Slip39Error.MALFORMED_SHARE,
            Slip39Error.PASSPHRASE, Slip39Error.SECRET_LENGTH, Slip39Error.INVALID_PARAMETERS,
            -> "$share isn't a valid recovery share. Check it against the paper."
        }
    }

    /** A Void-Which-Binds share: one group, 32 bytes, so 33 words (void-which-binds-go ADR-0011). */
    const val SHARE_WORDS = 33

    const val NOT_A_RECOVERY_SECRET =
        "That is a SLIP-39 share, but not of a Cruciform recovery secret (a wallet backup, perhaps)."

    const val MULTI_GROUP =
        "That share is from a backup split into several groups, which Cruciform can't combine. " +
            "Cruciform's own shares are a single group."

    private const val GENERIC = "That share could not be read. Check it against the paper."
}
