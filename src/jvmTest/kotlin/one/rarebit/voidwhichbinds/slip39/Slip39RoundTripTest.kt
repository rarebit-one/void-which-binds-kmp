package one.rarebit.voidwhichbinds.slip39

import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The properties the feature rests on, ported from void-which-binds-go's `slip39_test.go`:
 * every sufficient subset rebuilds the secret, one short is refused, and every way a
 * combination can be wrong is refused with its own typed error, naming the mnemonic
 * when it is about one.
 */
class Slip39RoundTripTest {

    private val rng = SecureRandom()

    private fun randomBytes(n: Int) = ByteArray(n).also(rng::nextBytes)

    /** Every k-element subset of 0 until n. */
    private fun subsets(n: Int, k: Int): List<List<Int>> = when {
        k == 0 -> listOf(emptyList())
        n < k -> emptyList()
        else -> subsets(n - 1, k - 1).map { it + (n - 1) } + subsets(n - 1, k)
    }

    /** Every choice of [spec]'s threshold of members from [members]. */
    private fun memberPicks(members: List<String>, spec: GroupSpec): List<List<String>> {
        val picks = subsets(spec.count, spec.threshold)
        return picks.map { ms -> ms.map { members[it] } }
    }

    /** Every set of mnemonics that meets the thresholds exactly. */
    private fun sufficientSets(shares: List<List<String>>, scheme: Slip39Scheme): List<List<String>> {
        val groupPicks = subsets(scheme.groups.size, scheme.groupThreshold)
        return groupPicks.flatMap { groupPick ->
            groupPick.fold(listOf(emptyList<String>())) { acc, g ->
                acc.flatMap { prefix -> memberPicks(shares[g], scheme.groups[g]).map { prefix + it } }
            }
        }
    }

    /**
     * Split a random [size]-byte secret under [scheme], then combine every sufficient
     * subset (in both orders) and check one short of each is refused.
     */
    private fun roundTrip(size: Int, scheme: Slip39Scheme) {
        val name = "$size bytes, extendable=${scheme.extendable}, ${scheme.groupThreshold} of ${scheme.groups}"
        val secret = randomBytes(size)
        val passphrase = if (scheme.extendable) "" else "correct horse"
        val shares = Slip39.split(secret, scheme, passphrase)
        val wordCount = if (size == 16) 20 else 33
        for ((g, spec) in scheme.groups.withIndex()) {
            assertEquals(spec.count, shares[g].size, name)
            shares[g].forEach { assertEquals(wordCount, it.split(" ").size, "$name: share length") }
        }
        val sets = sufficientSets(shares, scheme)
        assertTrue(sets.isNotEmpty(), name)
        for ((i, set) in sets.withIndex()) {
            val ordered = if (i % 2 == 1) set.reversed() else set
            assertContentEquals(secret, Slip39.combine(ordered, passphrase), "$name: subset $i")
            if (ordered.size == 1) continue
            val short = assertFailsWith<Slip39Exception> { Slip39.combine(ordered.dropLast(1), passphrase) }
            assertEquals(Slip39Error.INSUFFICIENT_SHARES, short.error, "$name: subset $i minus one")
        }
    }

    @Test
    fun everySufficientSubsetRebuildsTheSecret() {
        val layouts = listOf(
            1 to listOf(GroupSpec(1, 1)),
            1 to listOf(GroupSpec(2, 3)),
            1 to listOf(GroupSpec(3, 5)),
            1 to listOf(GroupSpec(5, 7)),
            2 to listOf(GroupSpec(2, 3), GroupSpec(1, 1), GroupSpec(3, 5)),
            3 to listOf(GroupSpec(1, 1), GroupSpec(2, 2), GroupSpec(2, 4), GroupSpec(1, 1)),
        )
        for (size in listOf(16, 32)) {
            for (extendable in listOf(true, false)) {
                for ((gt, groups) in layouts) roundTrip(size, Slip39Scheme(gt, groups, 0, extendable))
            }
        }
    }

    @Test
    fun theVoidbindProfileRoundTrips() {
        val secret = ByteArray(32) { 0x42 }
        val shares = Slip39.split(secret, Slip39Scheme(1, listOf(GroupSpec(2, 3)), iterationExponent = 1)).single()
        val s = Share.parse(shares[0])
        assertEquals(1, s.params.iterationExponent)
        assertTrue(s.params.extendable)
        assertEquals(2, s.memberThreshold)
        assertEquals(1, s.params.groupCount)
        assertContentEquals(secret, Slip39.combine(listOf(shares[2], shares[0])))
    }

    @Test
    fun splitRefusesBadParameters() {
        val secret = ByteArray(32)
        val twoOfThree = Slip39Scheme(1, listOf(GroupSpec(2, 3)))
        val bad = Slip39Error.INVALID_PARAMETERS
        val cases = mapOf(
            "short secret" to Triple(ByteArray(14), twoOfThree, Slip39Error.SECRET_LENGTH),
            "odd secret" to Triple(ByteArray(17), twoOfThree, Slip39Error.SECRET_LENGTH),
            "threshold > count" to Triple(secret, Slip39Scheme(1, listOf(GroupSpec(4, 3))), bad),
            "1-of-n" to Triple(secret, Slip39Scheme(1, listOf(GroupSpec(1, 3))), bad),
            "zero threshold" to Triple(secret, Slip39Scheme(1, listOf(GroupSpec(0, 3))), bad),
            "17 members" to Triple(secret, Slip39Scheme(1, listOf(GroupSpec(2, 17))), bad),
            "no groups" to Triple(secret, Slip39Scheme(1, emptyList()), bad),
            "group threshold > G" to Triple(secret, Slip39Scheme(2, listOf(GroupSpec(2, 3))), bad),
            "group threshold 0" to Triple(secret, Slip39Scheme(0, listOf(GroupSpec(2, 3))), bad),
            "exponent 16" to Triple(secret, twoOfThree.copy(iterationExponent = 16), bad),
        )
        for ((name, c) in cases) {
            val e = assertFailsWith<Slip39Exception>(name) { Slip39.split(c.first, c.second) }
            assertEquals(c.third, e.error, name)
        }
        val e = assertFailsWith<Slip39Exception> { Slip39.split(secret, twoOfThree, "pässword") }
        assertEquals(Slip39Error.PASSPHRASE, e.error)
    }

    /** Rebuild [m] after [mutate] changes its decoded share, with a VALID checksum. */
    private fun reencode(m: String, mutate: (Share) -> Share): String = mutate(Share.parse(m)).mnemonic()

    private fun Share.copy(
        params: SplitParams = this.params,
        memberThreshold: Int = this.memberThreshold,
        value: ByteArray = this.value.copyOf(),
    ) = Share(params, groupIndex, memberIndex, memberThreshold, value)

    private fun flipBit(value: ByteArray, at: Int) = value.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }

    @Test
    fun combineErrorsAreTyped() {
        val secret = randomBytes(32)
        fun split() = Slip39.split(secret, Slip39Scheme(1, listOf(GroupSpec(2, 3)))).single()
        val a = split()
        val b = split()
        fun swapWord(m: String, i: Int): String {
            val w = m.split(" ").toMutableList()
            w[i] = Slip39Wordlist.words[(Slip39Wordlist.indexOf(w[i])!! + 1) % Slip39Wordlist.SIZE]
            return w.joinToString(" ")
        }

        // A 32-byte value has 4 padding bits, the top of the first value word: set one and re-checksum.
        fun badPadding(m: String): String {
            val w = m.split(" ").map { Slip39Wordlist.indexOf(it)!! }.toIntArray()
            val data = w.copyOf(w.size - Rs1024.CHECKSUM_WORDS)
            data[4] = data[4] or (1 shl 9)
            return (data + Rs1024.checksum(true, data)).joinToString(" ") { Slip39Wordlist.words[it] }
        }
        val first = a[0].split(" ")
        val cases: Map<String, Triple<List<String>, Slip39Error, Int?>> = mapOf(
            "bad checksum names the mnemonic" to Triple(listOf(a[0], swapWord(a[1], 10)), Slip39Error.CHECKSUM, 1),
            "unknown word" to Triple(
                listOf(first.toMutableList().also { it[5] = "zzzz" }.joinToString(" "), a[1]),
                Slip39Error.UNKNOWN_WORD,
                0,
            ),
            "too short" to Triple(listOf(first.take(19).joinToString(" "), a[1]), Slip39Error.INVALID_LENGTH, 0),
            "mismatched identifier" to Triple(listOf(a[0], b[1]), Slip39Error.IDENTIFIER_MISMATCH, 1),
            "insufficient shares" to Triple(listOf(a[2]), Slip39Error.INSUFFICIENT_SHARES, null),
            "no shares" to Triple(emptyList(), Slip39Error.INSUFFICIENT_SHARES, null),
            "too many shares" to Triple(a, Slip39Error.TOO_MANY_SHARES, null),
            "duplicate index" to Triple(listOf(a[1], a[1]), Slip39Error.DUPLICATE_INDEX, 1),
            "bad padding" to Triple(listOf(a[0], badPadding(a[1])), Slip39Error.PADDING, 1),
            "digest mismatch" to Triple(
                listOf(a[0], reencode(a[1]) { s -> s.copy(value = flipBit(s.value, 7)) }),
                Slip39Error.DIGEST,
                null,
            ),
            "member threshold mismatch" to Triple(
                listOf(a[0], reencode(a[1]) { it.copy(memberThreshold = 3) }),
                Slip39Error.PARAMETER_MISMATCH,
                1,
            ),
            "group threshold above count" to Triple(
                listOf(reencode(a[0]) { it.copy(params = it.params.copy(groupThreshold = 2)) }, a[1]),
                Slip39Error.MALFORMED_SHARE,
                0,
            ),
        )
        for ((name, c) in cases) {
            val e = assertFailsWith<Slip39Exception>(name) { Slip39.combine(c.first) }
            assertEquals(c.second, e.error, "$name: ${e.message}")
            assertEquals(c.third, e.mnemonicIndex, "$name: ${e.message} blames the wrong mnemonic")
        }
        // The text a person reads names the mnemonic counting from 1.
        val e = assertFailsWith<Slip39Exception> { Slip39.combine(listOf(a[0], swapWord(a[1], 10))) }
        assertTrue("(mnemonic 2)" in e.message!!, e.message)
    }

    @Test
    fun transcribedFormsReadBack() {
        val secret = ByteArray(16) { 7 }
        val shares = Slip39.split(secret, Slip39Scheme(1, listOf(GroupSpec(2, 2)))).single()
        val messy = "  " + shares[0].replace(" ", "\n  ").uppercase() + "\t"
        assertContentEquals(secret, Slip39.combine(listOf(messy, shares[1])))
    }

    /** The spec's documented caveat: a wrong passphrase yields a different secret, not an error. */
    @Test
    fun aWrongPassphraseIsNotDetected() {
        val secret = ByteArray(32) { 9 }
        val shares = Slip39.split(secret, Slip39Scheme(1, listOf(GroupSpec(2, 3))), "right").single()
        val got = try {
            Slip39.combine(shares.take(2), "wrong")
        } catch (e: Slip39Exception) {
            fail("a wrong passphrase errored ($e); the spec says it cannot be detected")
        }
        assertFalse(got.contentEquals(secret), "a wrong passphrase recovered the secret")
    }

    @Test
    fun aRefusalWithoutAMnemonicNamesNone() {
        val e = Slip39Exception(Slip39Error.DIGEST)
        assertNull(e.mnemonicIndex)
        assertEquals(Slip39Error.DIGEST.message, e.message)
    }
}
