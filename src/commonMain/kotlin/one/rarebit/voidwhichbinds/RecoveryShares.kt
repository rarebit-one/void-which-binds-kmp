package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.slip39.GroupSpec
import one.rarebit.voidwhichbinds.slip39.Slip39
import one.rarebit.voidwhichbinds.slip39.Slip39Exception
import one.rarebit.voidwhichbinds.slip39.Slip39Scheme

/**
 * The Void-Which-Binds SLIP-39 profile (void-which-binds-go ADR-0011): a [RecoverySecret]'s 32
 * bytes split k-of-n as a single group, iteration exponent 1, extendable, no
 * passphrase by default. Combining yields the identical secret, so the identical
 * identity: nothing about the secret, its labels or its bech32m form changes. A
 * share is only another way of writing the secret down. Mirrors void-which-binds-go
 * `recovery.SplitShares` / `recovery.CombineShares`.
 */
object RecoveryShares {
    /** The household default: any 2 of 3 shares. */
    const val DEFAULT_THRESHOLD = 2
    const val DEFAULT_COUNT = 3

    /**
     * 10000·2¹ PBKDF2 iterations. They only stretch a passphrase, and the secret is
     * already 256 bits of entropy, so this stays at Trezor's default.
     */
    const val ITERATION_EXPONENT = 1

    /** SLIP-39's extendable-backup flag, which new shares SHOULD set (Trezor's default). */
    const val EXTENDABLE = true

    /**
     * Split [secret] into [count] mnemonics, any [threshold] of which rebuild it.
     * [passphrase] may be empty, which is the default and the recommendation: a
     * forgotten one loses the secret, and a wrong one silently rebuilds a DIFFERENT
     * secret, which only an identity check after [combine] catches.
     *
     * Splitting revokes nothing: the bech32m secret keeps working on its own.
     */
    @Throws(IllegalArgumentException::class)
    fun split(
        secret: RecoverySecret,
        threshold: Int = DEFAULT_THRESHOLD,
        count: Int = DEFAULT_COUNT,
        passphrase: String = "",
    ): List<String> {
        require(threshold >= 1 && count >= 1 && count <= Slip39.MAX_SHARE_COUNT) {
            "recovery: $threshold-of-$count shares: want 1 <= threshold <= shares <= ${Slip39.MAX_SHARE_COUNT}"
        }
        require(threshold <= count) {
            "recovery: a threshold of $threshold needs at least $threshold shares, not $count"
        }
        require(threshold > 1 || count == 1) {
            "recovery: a threshold of 1 makes $count copies of the secret, not shares of it; " +
                "use a threshold of at least 2"
        }
        val scheme = Slip39Scheme(1, listOf(GroupSpec(threshold, count)), ITERATION_EXPONENT, EXTENDABLE)
        return Slip39.split(secret.bytes, scheme, passphrase).single()
    }

    /**
     * Rebuild a [RecoverySecret] from SLIP-39 [mnemonics]. Any set SLIP-39 can combine
     * is taken (not only one [split] made), provided it holds 32 bytes. A mistyped
     * share is refused by its checksum and named, shares of different splits are
     * refused, and too few or too many are refused ([Slip39Exception]), so a bad share
     * never becomes a wrong identity. A set holding any other length is refused as
     * [NotARecoverySecretException]. The one thing it cannot catch is a wrong
     * passphrase: compare the result's identity with the pinned one.
     */
    @Throws(IllegalArgumentException::class)
    fun combine(mnemonics: List<String>, passphrase: String = ""): RecoverySecret {
        val secret = Slip39.combine(mnemonics, passphrase)
        if (secret.size != Labels.RECOVERY_SECRET_LEN) throw NotARecoverySecretException(secret.size)
        return RecoverySecret.of(secret)
    }

    /**
     * How far along a set being entered one share at a time is, without combining it.
     * Each of [mnemonics] is checked as [combine] would check it (it decodes, belongs
     * with the first, and repeats no share), so a bad share is refused the moment it
     * is added, named by its [Slip39Exception.mnemonicIndex]. A set that does not hold
     * a recovery secret is refused as [NotARecoverySecretException].
     */
    @Throws(IllegalArgumentException::class)
    fun progress(mnemonics: List<String>): Progress {
        if (mnemonics.isEmpty()) return Progress(given = 0, needed = null)
        val set = Slip39.decode(mnemonics)
        val length = set.groups.first().members.first().y.size
        if (length != Labels.RECOVERY_SECRET_LEN) throw NotARecoverySecretException(length)
        val singleGroup = set.params.groupCount == 1
        return Progress(given = mnemonics.size, needed = if (singleGroup) set.groups.single().threshold else null)
    }

    /**
     * [given] shares entered of the [needed] the set's threshold asks for. [needed] is
     * null before the first share, and for a multi-group backup, whose total no one
     * share states (Void-Which-Binds makes single-group sets; [combine] still takes others).
     */
    data class Progress(val given: Int, val needed: Int?) {
        /** Exactly enough shares to combine. */
        val complete: Boolean get() = needed != null && given == needed
    }
}

/**
 * SLIP-39 shares that combine, but to a secret that is not 32 bytes (a 128-bit wallet
 * backup, say), so they are not a void-which-binds recovery secret. Refused rather than
 * padded into an identity.
 */
class NotARecoverySecretException(val secretLength: Int) :
    IllegalArgumentException(
        "recovery: these shares hold a $secretLength-byte secret, so they are not a void-which-binds recovery secret " +
            "(a wallet backup?)",
    )
