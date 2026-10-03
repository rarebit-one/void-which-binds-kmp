package one.rarebit.voidwhichbinds.approval

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.GoStrings
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.scope.Scope
import one.rarebit.voidwhichbinds.scope.ScopeException

/**
 * What a person is asked to approve (void-which-binds-go `approval.Action`, ADR-0019).
 *
 * - [kind]: a short verb, `[a-z][a-z0-9-]{0,31}`, such as `deploy`;
 * - [resource]: one ADR-0017 scope ([Scope.validate]), such as `do:team/ops`;
 * - [summary]: the sentence the approver displays, 1–[Approval.MAX_SUMMARY_LEN] bytes of
 *   valid UTF-8 with no control (Unicode Cc) and no explicit bidirectional-formatting
 *   character. It is digested as given; nothing is normalised;
 * - [params]: opaque bytes, at most [Approval.MAX_PARAMS_LEN], possibly empty. The
 *   broker canonicalised them once when it built the action; the approver recomputes the
 *   digest over the bytes it fetched and never canonicalises them again.
 */
class Action(val kind: String, val resource: String, val summary: String, params: ByteArray) {
    private val p: ByteArray = params.copyOf()

    /** A copy of the params bytes. */
    val params: ByteArray get() = p.copyOf()

    /**
     * Refuses this action ([Approval.Failure.MALFORMED]) unless it keeps every grammar
     * rule, naming the first it breaks, in Go `Action.Check`'s order: kind, resource,
     * summary, params.
     */
    @Throws(Exception::class)
    fun check() {
        checkKind(kind)?.let { Approval.fail(Approval.Failure.MALFORMED, "kind: $it") }
        try {
            Scope.validate(resource)
        } catch (e: ScopeException) {
            Approval.fail(Approval.Failure.MALFORMED, "resource: ${e.message}")
        }
        checkSummary(summary)?.let { Approval.fail(Approval.Failure.MALFORMED, "summary: $it") }
        if (p.size > Approval.MAX_PARAMS_LEN) {
            Approval.fail(Approval.Failure.MALFORMED, "params: ${p.size} bytes, over ${Approval.MAX_PARAMS_LEN}")
        }
    }

    /**
     * ADR-0019's action digest, after [check]:
     *
     *     SHA-256( frame(DOMAIN_ACTION) ‖ frame(kind) ‖ frame(resource) ‖ frame(summary) ‖ frame(params) )
     *
     * Go `Action.Digest`.
     */
    @Throws(Exception::class)
    fun digest(): ByteArray {
        check()
        val b = Frames()
            .add(Approval.DOMAIN_ACTION.encodeToByteArray())
            .add(kind.encodeToByteArray())
            .add(resource.encodeToByteArray())
            .add(summary.encodeToByteArray())
            .add(p)
            .bytes()
        return sha256.hashBlocking(b)
    }

    override fun equals(other: Any?): Boolean = other is Action && other.kind == kind &&
        other.resource == resource && other.summary == summary && other.p.contentEquals(p)

    override fun hashCode(): Int = (
        (kind.hashCode() * HASH_MUL + resource.hashCode()) * HASH_MUL +
            summary.hashCode()
        ) * HASH_MUL + p.contentHashCode()

    override fun toString(): String = "Action(kind=$kind, resource=$resource, summary=$summary, params=${p.size} bytes)"

    private companion object {
        const val HASH_MUL = 31
        val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

        /** Go `checkKind`: 1–32 bytes of `[a-z][a-z0-9-]*`. */
        @Suppress("ReturnCount")
        fun checkKind(k: String): String? {
            val n = GoStrings.utf8Length(k)
            if (n == 0 || n > Approval.MAX_KIND_LEN) return "$n bytes; a kind is 1 to ${Approval.MAX_KIND_LEN}"
            for ((i, c) in k.withIndex()) {
                val ok = c in 'a'..'z' || (i > 0 && (c in '0'..'9' || c == '-'))
                if (!ok) return "\"$k\" is not [a-z][a-z0-9-]*"
            }
            return null
        }

        /**
         * Go `checkSummary`: 1–1024 bytes, valid UTF-8 (a lone surrogate is not), and no
         * rune that is `unicode.IsControl` (C0 and C1: U+0000–U+001F, U+007F–U+009F) or an
         * explicit bidirectional-formatting character.
         */
        @Suppress("ReturnCount")
        fun checkSummary(s: String): String? {
            val n = GoStrings.utf8Length(s)
            if (n == 0 || n > Approval.MAX_SUMMARY_LEN) return "$n bytes; a summary is 1 to ${Approval.MAX_SUMMARY_LEN}"
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) {
                    i += 2 // a supplementary rune: never Cc, never a bidi format character
                    continue
                }
                if (c.isSurrogate()) return "not valid UTF-8"
                i++
            }
            for (c in s) {
                if (isControl(c) || isBidiFormat(c)) {
                    return "contains U+${c.code.toString(HEX_RADIX).uppercase().padStart(HEX_DIGITS, '0')}, " +
                        "a control or bidirectional-formatting character"
                }
            }
            return null
        }

        private const val HEX_RADIX = 16
        private const val HEX_DIGITS = 4

        /** Go `unicode.IsControl`: Cc is exactly C0 and C1 (every rune past U+00FF answers false). */
        @Suppress("MagicNumber")
        private fun isControl(c: Char): Boolean = c.code < 0x20 || c.code in 0x7F..0x9F

        /** UAX #9's explicit formatting characters: U+202A–U+202E, U+2066–U+2069, U+200E, U+200F, U+061C. */
        @Suppress("MagicNumber")
        private fun isBidiFormat(c: Char): Boolean =
            c.code in 0x202A..0x202E || c.code in 0x2066..0x2069 || c.code == 0x200E || c.code == 0x200F ||
                c.code == 0x061C
    }
}

/**
 * One approval ceremony (void-which-binds-go `approval.Challenge`, ADR-0019), as the
 * approver holds it after [FetchResponse.open]. On the approver's side [matchNumber] is
 * 0 and unused: the approver signs the number the person chose among [candidates]
 * ([Approval.signAssertionWith] / [Approval.passkeyChallenge] bind it in).
 *
 * @property id the challenge id: 16 random bytes as 32 lowercase hex characters.
 * @property nonce the per-ceremony RP nonce (ADR-0018), 32 bytes, never all zero.
 * @property audience the broker's origin.
 * @property issuedAt unix seconds; not in the preimage.
 * @property expiresAt unix seconds, after the epoch.
 * @property candidates the numbers the phone shows (the true one and decoys).
 * @property actionDigest the action's [Action.digest], 32 bytes.
 * @property resource the action's resource, framed on its own.
 * @property ttlSeconds how long the approval authorises the action once given:
 *   0 is single use, at most [Approval.MAX_APPROVAL_TTL_SECONDS].
 */
@Suppress("LongParameterList")
class Challenge(
    val id: String,
    nonce: ByteArray,
    val audience: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val matchNumber: Int,
    val candidates: List<Int>,
    actionDigest: ByteArray,
    val resource: String,
    val ttlSeconds: Long,
) {
    private val n: ByteArray = nonce.copyOf()
    private val d: ByteArray = actionDigest.copyOf()

    /** A copy of the nonce. */
    val nonce: ByteArray get() = n.copyOf()

    /** A copy of the action digest. */
    val actionDigest: ByteArray get() = d.copyOf()

    /** This challenge with [chosen] in place of its own number: what an approver signs. */
    fun withMatchNumber(chosen: Int): Challenge =
        Challenge(id, n, audience, issuedAt, expiresAt, chosen, candidates, d, resource, ttlSeconds)

    /**
     * The exact bytes an approver signs (ADR-0019):
     *
     *     frame(DOMAIN_CHALLENGE)
     *     frame(id) frame(nonce) frame(audience) frame(uint64be(expiresAt))
     *     frame(uint64be(matchNumber)) frame(actionDigest) frame(resource) frame(uint64be(ttlSeconds))
     *
     * Refuses ([Approval.Failure.MALFORMED]; an over-long ttl is
     * [Approval.Failure.TTL_TOO_LONG], whose word is also `malformed`), in Go
     * `Challenge.check`'s order: an id that is not 32 lowercase hex characters, an
     * all-zero (or not 32-byte) nonce, an empty audience, an expiry at or before the
     * epoch, a match number outside `[0, 100)`, a resource outside the scope grammar, a
     * negative or over-long ttl. A digest that is not 32 bytes is refused too (Go's is a
     * fixed array). Go `Challenge.Preimage`.
     */
    @Throws(Exception::class)
    fun preimage(): ByteArray {
        checkFields()
        return Frames()
            .add(Approval.DOMAIN_CHALLENGE.encodeToByteArray())
            .add(id.encodeToByteArray())
            .add(n)
            .add(audience.encodeToByteArray())
            .add(Frames.u64(expiresAt))
            .add(Frames.u64(matchNumber.toLong()))
            .add(d)
            .add(resource.encodeToByteArray())
            .add(Frames.u64(ttlSeconds))
            .bytes()
    }

    private fun checkFields() {
        val m = Approval.Failure.MALFORMED
        if (!isChallengeId(id)) Approval.fail(m, "id: \"$id\" is not ${2 * Approval.ID_LEN} lowercase hex characters")
        if (n.size != Approval.NONCE_LEN || n.all { it == 0.toByte() }) Approval.fail(m, "the nonce is all zero")
        if (audience.isEmpty()) Approval.fail(m, "empty audience")
        if (expiresAt <= 0) Approval.fail(m, "expires_at $expiresAt is not after the epoch")
        if (matchNumber !in 0 until Approval.MATCH_NUMBER_BOUND) {
            Approval.fail(m, "match number $matchNumber is outside [0, ${Approval.MATCH_NUMBER_BOUND})")
        }
        try {
            Scope.validate(resource)
        } catch (e: ScopeException) {
            Approval.fail(m, "resource: ${e.message}")
        }
        if (ttlSeconds < 0) Approval.fail(m, "ttl ${ttlSeconds}s is negative")
        if (ttlSeconds > Approval.MAX_APPROVAL_TTL_SECONDS) {
            Approval.fail(
                Approval.Failure.TTL_TOO_LONG,
                "ttl ${ttlSeconds}s > ${Approval.MAX_APPROVAL_TTL_SECONDS}s",
            )
        }
        if (d.size != Approval.DIGEST_LEN) Approval.fail(m, "the action digest is ${d.size} bytes")
    }

    /**
     * Whether [a] is the action this challenge was minted for: its digest (after
     * [Action.check], `malformed`) is [actionDigest] ([Approval.Failure.DIGEST_MISMATCH]),
     * and its resource is [resource] ([Approval.Failure.RESOURCE_MISMATCH]). Go
     * `Challenge.matches`.
     */
    internal fun requireMatches(a: Action) {
        if (!a.digest().contentEquals(d)) {
            Approval.fail(Approval.Failure.DIGEST_MISMATCH, "the action does not recompute to the challenge's digest")
        }
        if (a.resource != resource) {
            Approval.fail(Approval.Failure.RESOURCE_MISMATCH, "the action names ${a.resource}, the challenge $resource")
        }
    }

    override fun toString(): String =
        "Challenge(id=$id, audience=$audience, expiresAt=$expiresAt, candidates=$candidates, " +
            "actionDigest=${Hex.encode(d)}, resource=$resource, ttlSeconds=$ttlSeconds)"

    private companion object {
        /** Go `checkID`: 32 characters, lowercase, hex. */
        fun isChallengeId(id: String): Boolean =
            id.length == 2 * Approval.ID_LEN && id.all { it in '0'..'9' || it in 'a'..'f' }
    }
}

/** frame(p) = uint64be(len(p)) ‖ p, appended in order (Go `frame`). */
internal class Frames {
    private val parts = ArrayList<ByteArray>()

    fun add(p: ByteArray): Frames {
        parts.add(u64(p.size.toLong()))
        parts.add(p.copyOf())
        return this
    }

    fun bytes(): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var at = 0
        for (p in parts) {
            p.copyInto(out, at)
            at += p.size
        }
        return out
    }

    companion object {
        private const val U64_LEN = 8
        private const val BYTE_BITS = 8

        /** uint64be(v), v read as unsigned (Go `binary.BigEndian.AppendUint64`). */
        fun u64(v: Long): ByteArray = ByteArray(U64_LEN) { i -> (v ushr (BYTE_BITS * (U64_LEN - 1 - i))).toByte() }
    }
}
