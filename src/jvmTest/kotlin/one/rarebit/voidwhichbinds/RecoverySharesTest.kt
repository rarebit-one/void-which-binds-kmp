package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.slip39.GroupSpec
import one.rarebit.voidwhichbinds.slip39.Slip39
import one.rarebit.voidwhichbinds.slip39.Slip39Error
import one.rarebit.voidwhichbinds.slip39.Slip39Exception
import one.rarebit.voidwhichbinds.slip39.Slip39Scheme
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The voidbind SLIP-39 profile ([RecoveryShares], void-which-binds-go ADR-0011), and the
 * cross-language proof: shares made by void-which-binds-go's CLI combine here to the secret
 * they were split from, so the same identity.
 */
class RecoverySharesTest {

    /**
     * void-which-binds-go's `counting-entropy` recovery vector (00 01 … 1f): its bech32m
     * secret, user identity and fingerprint are pinned in `vectors/recovery/`.
     */
    private val secretText = "heyarr1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6e0ucu"
    private val userId = "ed25519:40521a413f04f5e76d309dc8aebd8980d877291e62fedbf573ed3b45f7aa54a0"
    private val fingerprint = "PYJI XGNZ K7ZH XHEJ"

    /**
     * Made on 2026-09-25 by void-which-binds-go (the unmerged `recovery-slip39` branch, ADR-0011):
     * `echo <secretText> | go run ./cmd/void-which-binds recovery split --secret-file -`, which
     * printed the user and fingerprint above. Test data only: the secret is public.
     */
    private val goShares = listOf(
        "regular agency academic acid avoid erode echo health fatigue thunder calcium iris change network " +
            "swimming funding painting inherit infant cricket bedroom hour income brother worthy agree sugar " +
            "apart charity snapshot universe behavior budget",
        "regular agency academic agency adapt desktop always grief patrol eclipse goat destroy estate froth " +
            "obtain elevator lunch evidence eraser carbon trend oasis envelope damage trip spray analysis " +
            "luxury trip scholar trend income teaspoon",
        "regular agency academic always admit decorate smug include acrobat trash texture vocal fishing " +
            "space fancy amazing tenant mayor amazing dance username acrobat ajar carbon gesture pharmacy " +
            "group airline picture dough revenue pupal advocate",
    )

    @Test
    fun everyPairOfGoSharesRebuildsTheGoSecret() {
        val pairs = listOf(0 to 1, 0 to 2, 1 to 2, 2 to 0)
        for ((i, j) in pairs) {
            val secret = RecoverySecret.fromShares(listOf(goShares[i], goShares[j]))
            assertEquals(secretText, secret.format(), "shares ${i + 1} and ${j + 1}")
            val user = UserIdentity.fromSecret(secret)
            assertEquals(userId, user.userId.render())
            assertEquals(fingerprint, user.fingerprint)
        }
    }

    @Test
    fun goSharesFollowTheProfile() {
        assertEquals(RecoveryShares.Progress(given = 1, needed = 2), RecoveryShares.progress(goShares.take(1)))
        assertTrue(RecoveryShares.progress(goShares.take(2)).complete)
        goShares.forEach { assertEquals(33, it.split(" ").size) }
    }

    @Test
    fun splitThenCombineIsTheSameSecret() {
        val secret = RecoverySecret.parse(secretText)
        for ((k, n) in listOf(2 to 3, 3 to 5, 2 to 2, 1 to 1)) {
            val shares = secret.splitShares(k, n)
            assertEquals(n, shares.size)
            // Every k-subset, taken as consecutive runs (enough for small n; the
            // exhaustive property is Slip39RoundTripTest's).
            for (start in 0 until n) {
                val subset = List(k) { shares[(start + it) % n] }
                assertEquals(secret, RecoverySecret.fromShares(subset), "$k-of-$n from ${start + 1}")
            }
        }
        // Every split is its own set: two splits of one secret don't mix.
        val a = secret.splitShares()
        val b = secret.splitShares()
        val mixed = assertFailsWith<Slip39Exception> { RecoverySecret.fromShares(listOf(a[0], b[1])) }
        assertEquals(Slip39Error.IDENTIFIER_MISMATCH, mixed.error)
        assertEquals(1, mixed.mnemonicIndex)
    }

    @Test
    fun splitRefusesWhatGoRefuses() {
        val secret = RecoverySecret.parse(secretText)
        for ((k, n) in listOf(3 to 2, 1 to 3, 0 to 3, 2 to 17, 2 to 0)) {
            assertFailsWith<IllegalArgumentException>("$k-of-$n") { secret.splitShares(k, n) }
        }
    }

    @Test
    fun aWalletBackupIsNotARecoverySecret() {
        // A valid 128-bit set (as a wallet makes), which must not become an identity.
        val shares = Slip39.split(ByteArray(16) { 1 }, Slip39Scheme(1, listOf(GroupSpec(2, 3)))).single()
        val combined = assertFailsWith<NotARecoverySecretException> { RecoverySecret.fromShares(shares.take(2)) }
        assertEquals(16, combined.secretLength)
        // …and entering one share by one refuses it at the first.
        assertFailsWith<NotARecoverySecretException> { RecoveryShares.progress(shares.take(1)) }
    }

    @Test
    fun progressRefusesABadShareTheMomentItIsAdded() {
        assertEquals(RecoveryShares.Progress(0, null), RecoveryShares.progress(emptyList()))
        assertFalse(RecoveryShares.Progress(0, null).complete)

        val duplicate = assertFailsWith<Slip39Exception> { RecoveryShares.progress(listOf(goShares[1], goShares[1])) }
        assertEquals(Slip39Error.DUPLICATE_INDEX, duplicate.error)
        assertEquals(1, duplicate.mnemonicIndex)

        val otherSet = RecoverySecret.parse(secretText).splitShares()
        val mixed = assertFailsWith<Slip39Exception> { RecoveryShares.progress(listOf(goShares[0], otherSet[1])) }
        assertEquals(Slip39Error.IDENTIFIER_MISMATCH, mixed.error)

        val words = goShares[2].split(" ").toMutableList()
        words[7] = if (words[7] == "acid") "acne" else "acid"
        val mistyped = words.joinToString(" ")
        val typo = assertFailsWith<Slip39Exception> { RecoveryShares.progress(listOf(goShares[0], mistyped)) }
        assertEquals(Slip39Error.CHECKSUM, typo.error)
        assertEquals(1, typo.mnemonicIndex)
    }

    @Test
    fun aMultiGroupSetHasNoKnownTotal() {
        val scheme = Slip39Scheme(2, listOf(GroupSpec(2, 3), GroupSpec(2, 3)), iterationExponent = 0)
        val shares = Slip39.split(ByteArray(32) { 5 }, scheme)
        val progress = RecoveryShares.progress(listOf(shares[0][0]))
        assertNull(progress.needed)
        assertFalse(progress.complete)
        // combine still takes it: any SLIP-39 set holding 32 bytes.
        val secret = RecoverySecret.fromShares(listOf(shares[0][0], shares[0][2], shares[1][1], shares[1][0]))
        assertEquals(RecoverySecret.of(ByteArray(32) { 5 }), secret)
    }
}
