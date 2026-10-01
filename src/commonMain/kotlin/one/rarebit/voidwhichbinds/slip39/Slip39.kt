package one.rarebit.voidwhichbinds.slip39

import dev.whyoleg.cryptography.random.CryptographyRandom

/** One group of a split: [count] member shares, any [threshold] of which rebuild the group's share. */
data class GroupSpec(val threshold: Int, val count: Int)

/**
 * How [Slip39.split] shares a secret: [groupThreshold] of [groups], each group split
 * again per its [GroupSpec]; [iterationExponent] sets 10000·2^e PBKDF2 iterations;
 * [extendable] sets the extendable-backup flag, which new shares SHOULD set (the
 * identifier then does not salt the encryption, so every set split from one secret
 * decrypts to it). For a plain T-of-N the spec says to use one group:
 * `Slip39Scheme(1, listOf(GroupSpec(T, N)))`.
 */
data class Slip39Scheme(
    val groupThreshold: Int,
    val groups: List<GroupSpec>,
    val iterationExponent: Int = 0,
    val extendable: Boolean = true,
)

/**
 * SLIP-0039, "Shamir's Secret-Sharing for Mnemonic Codes"
 * (https://github.com/satoshilabs/slips/blob/master/slip-0039.md), including the
 * extendable-backup revision: a line-for-line port of void-which-binds-go `recovery/slip39`
 * (void-which-binds-go ADR-0011), passing every one of Trezor's 45 published vectors
 * (`vectors/slip39/vectors.json`, replayed by `Slip39VectorTest`).
 *
 * The package is generic: it splits and combines any master secret the spec allows.
 * The Void-Which-Binds profile, which fixes the parameters for a recovery secret, is
 * [one.rarebit.voidwhichbinds.RecoveryShares].
 *
 * Unlike plain Shamir, a bad share is refused rather than silently rebuilding a
 * different secret: an RS1024 checksum catches any error in up to three words, the
 * shares' metadata stops shares that do not belong together before any maths, and
 * a digest share at x=254 checks the rebuilt secret. Every refusal is a typed
 * [Slip39Exception].
 */
object Slip39 {
    /** The most groups, and the most members of one group, a share's 4-bit fields address. */
    const val MAX_SHARE_COUNT = 16

    /** The shortest master secret: 128 bits. It must also be a whole number of 16-bit units. */
    const val MIN_SECRET_BYTES = 16

    /** The largest iteration exponent the 4-bit field holds. */
    const val MAX_ITERATION_EXPONENT = 15

    private const val PRINTABLE_FIRST = ' '
    private const val PRINTABLE_LAST = '~'
    private const val ID_BYTES = 2
    private const val BYTE_BITS = 8
    private const val BYTE_MASK = 0xff
    private const val ID_MASK = (1 shl Share.ID_BITS) - 1

    private val systemRandom: (Int) -> ByteArray = { CryptographyRandom.Default.nextBytes(it) }

    /**
     * Share [masterSecret] under [scheme] and [passphrase]: one list of mnemonics per
     * group, in group order, members in index order. [random] must be suitable for
     * keys (every random share, the identifier and the digest key come from it); it
     * defaults to the platform CSPRNG.
     *
     * @throws Slip39Exception [Slip39Error.SECRET_LENGTH], [Slip39Error.PASSPHRASE] or
     *   [Slip39Error.INVALID_PARAMETERS].
     */
    @Throws(Slip39Exception::class)
    fun split(
        masterSecret: ByteArray,
        scheme: Slip39Scheme,
        passphrase: String = "",
        random: (Int) -> ByteArray = systemRandom,
    ): List<List<String>> {
        if (masterSecret.size < MIN_SECRET_BYTES || masterSecret.size % 2 != 0) {
            refuse(Slip39Error.SECRET_LENGTH, "got ${masterSecret.size} bytes")
        }
        val pass = passphraseBytes(passphrase)
        validate(scheme)
        val draw = { n: Int ->
            random(n).also { check(it.size == n) { "slip39: the random source gave ${it.size} bytes, not $n" } }
        }

        val idBytes = draw(ID_BYTES)
        val id = (((idBytes[0].toInt() and BYTE_MASK) shl BYTE_BITS) or (idBytes[1].toInt() and BYTE_MASK)) and ID_MASK
        val params = SplitParams(
            id = id,
            extendable = scheme.extendable,
            iterationExponent = scheme.iterationExponent,
            groupThreshold = scheme.groupThreshold,
            groupCount = scheme.groups.size,
        )
        val encrypted = Feistel.encrypt(masterSecret, pass, params)
        val groupShares = Shamir.split(scheme.groupThreshold, scheme.groups.size, encrypted, draw)
        return scheme.groups.mapIndexed { gi, g ->
            Shamir.split(g.threshold, g.count, groupShares[gi], draw).mapIndexed { mi, value ->
                Share(params, groupIndex = gi, memberIndex = mi, memberThreshold = g.threshold, value = value)
                    .mnemonic()
            }
        }
    }

    private fun validate(scheme: Slip39Scheme) {
        val groups = scheme.groups
        if (scheme.iterationExponent !in 0..MAX_ITERATION_EXPONENT) {
            refuse(
                Slip39Error.INVALID_PARAMETERS,
                "iteration exponent ${scheme.iterationExponent} is not in 0..$MAX_ITERATION_EXPONENT",
            )
        }
        if (groups.size !in 1..MAX_SHARE_COUNT) {
            refuse(Slip39Error.INVALID_PARAMETERS, "${groups.size} groups, want 1..$MAX_SHARE_COUNT")
        }
        if (scheme.groupThreshold !in 1..groups.size) {
            refuse(
                Slip39Error.INVALID_PARAMETERS,
                "group threshold ${scheme.groupThreshold} with ${groups.size} groups",
            )
        }
        for ((i, g) in groups.withIndex()) {
            if (g.count !in 1..MAX_SHARE_COUNT || g.threshold !in 1..g.count) {
                refuse(
                    Slip39Error.INVALID_PARAMETERS,
                    "group ${i + 1} is ${g.threshold}-of-${g.count}, want 1 <= threshold <= count <= $MAX_SHARE_COUNT",
                )
            }
            if (g.threshold == 1 && g.count > 1) {
                refuse(
                    Slip39Error.INVALID_PARAMETERS,
                    "group ${i + 1} is 1-of-${g.count}; a member threshold of 1 needs a group of one " +
                        "(give the one share to several people instead)",
                )
            }
        }
    }

    /**
     * Rebuild the master secret from [mnemonics] and [passphrase]. It needs exactly the
     * group threshold's worth of groups and, of each, exactly that group's member
     * threshold of mnemonics, in any order.
     *
     * A problem with one mnemonic (an unknown word, a bad checksum or padding, a share
     * that does not belong with the first one, a repeated share) is a
     * [Slip39Exception] whose [Slip39Exception.mnemonicIndex] names it; a problem with
     * the set (too few or too many shares, a failed digest) names none.
     *
     * A wrong passphrase is NOT detected: by the spec's design it decrypts to a
     * different, valid-looking secret. Check the result against something known, as
     * Void-Which-Binds does against the pinned identity.
     */
    @Throws(Slip39Exception::class)
    fun combine(mnemonics: List<String>, passphrase: String = ""): ByteArray {
        if (mnemonics.isEmpty()) refuse(Slip39Error.INSUFFICIENT_SHARES, "no mnemonics given")
        val pass = passphraseBytes(passphrase)
        val set = decode(mnemonics)
        val params = set.params
        if (set.groups.size < params.groupThreshold) {
            refuse(
                Slip39Error.INSUFFICIENT_SHARES,
                "shares from ${set.groups.size} group(s), ${params.groupThreshold} needed",
            )
        }
        if (set.groups.size > params.groupThreshold) {
            refuse(
                Slip39Error.TOO_MANY_SHARES,
                "shares from ${set.groups.size} groups, exactly ${params.groupThreshold} needed",
            )
        }
        val groupShares = set.groups.map { g -> Point(g.index, recoverGroup(g, params.groupCount)) }
        return Feistel.decrypt(Shamir.recover(params.groupThreshold, groupShares), pass, params)
    }

    private fun recoverGroup(g: Group, groupCount: Int): ByteArray {
        val ofGroup = if (groupCount > 1) " of group ${g.index + 1}" else "" // a single group has no name worth giving
        if (g.members.size < g.threshold) {
            refuse(Slip39Error.INSUFFICIENT_SHARES, "${g.members.size} share(s)$ofGroup given, ${g.threshold} needed")
        }
        if (g.members.size > g.threshold) {
            refuse(Slip39Error.TOO_MANY_SHARES, "${g.members.size} shares$ofGroup given, exactly ${g.threshold} needed")
        }
        return Shamir.recover(g.threshold, g.members)
    }

    /** A decoded, mutually consistent set of shares, grouped in the order groups first appear. */
    internal class DecodedSet(val params: SplitParams, val groups: List<Group>)

    internal class Group(val index: Int, val threshold: Int) {
        val members = ArrayList<Point>()
    }

    /**
     * Everything [combine] checks before counting shares or doing any maths: each
     * mnemonic decodes, each belongs with the first (identifier, then parameters,
     * then length), and no member index repeats within a group. Every refusal names
     * its mnemonic.
     */
    internal fun decode(mnemonics: List<String>): DecodedSet {
        val shares = mnemonics.mapIndexed { i, m -> attributed(i) { Share.parse(m) } }
        val first = shares[0]
        for (i in 1 until shares.size) attributed(i) { checkBelongs(shares[i], first) }

        val groups = LinkedHashMap<Int, Group>()
        for ((i, s) in shares.withIndex()) {
            val g = groups.getOrPut(s.groupIndex) { Group(s.groupIndex, s.memberThreshold) }
            attributed(i) { admit(g, s) }
        }
        return DecodedSet(first.params, groups.values.toList())
    }

    private fun admit(g: Group, s: Share) {
        if (s.memberThreshold != g.threshold) {
            refuse(
                Slip39Error.PARAMETER_MISMATCH,
                "its member threshold differs from another share of group ${s.groupIndex + 1}",
            )
        }
        if (g.members.any { it.x == s.memberIndex }) {
            refuse(
                Slip39Error.DUPLICATE_INDEX,
                "group ${s.groupIndex + 1} member ${s.memberIndex + 1} was already given",
            )
        }
        g.members += Point(s.memberIndex, s.value)
    }

    private fun checkBelongs(s: Share, first: Share) {
        val a = s.params
        val b = first.params
        if (a.id != b.id) {
            refuse(Slip39Error.IDENTIFIER_MISMATCH, "it does not start with the same two words as mnemonic 1")
        }
        val mismatch = when {
            a.extendable != b.extendable || a.iterationExponent != b.iterationExponent ->
                "its iteration exponent or extendable flag differs from mnemonic 1"

            a.groupThreshold != b.groupThreshold || a.groupCount != b.groupCount ->
                "its group threshold or group count differs from mnemonic 1"

            s.value.size != first.value.size -> "it is a different length from mnemonic 1"

            else -> null
        }
        if (mismatch != null) refuse(Slip39Error.PARAMETER_MISMATCH, mismatch)
    }

    /** Run [block], attributing any [Slip39Exception] it throws to mnemonic [index]. */
    private inline fun <T> attributed(index: Int, block: () -> T): T = try {
        block()
    } catch (e: Slip39Exception) {
        throw e.at(index)
    }

    private fun passphraseBytes(passphrase: String): ByteArray {
        if (passphrase.any { it !in PRINTABLE_FIRST..PRINTABLE_LAST }) refuse(Slip39Error.PASSPHRASE)
        return passphrase.encodeToByteArray()
    }
}
