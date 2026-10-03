package one.rarebit.voidwhichbinds.approval

import one.rarebit.voidwhichbinds.approval.Approval.Failure
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.GoJson

/**
 * An approver's answer to a challenge: the body it posts to approve (ADR-0019,
 * "Encodings"). [credential] is the admitting op token; [ops] and [roster] are the
 * presented person and roster ops (each op is signed on its own, so neither is in the
 * signature); [sig] is unpadded base64url of an Ed25519 key's 64 bytes or a passkey's
 * ADR-0018 envelope; [matchNumber] is the number the person chose. Go `approval.Assertion`.
 */
class Assertion(
    val credential: String,
    val ops: List<String>,
    val roster: List<String>,
    val sig: String,
    val matchNumber: Int?,
) {
    /**
     * The JSON body exactly as Go's `json.Marshal` renders `approval.Assertion`:
     * `{"credential","ops","roster","sig","match_number"}` in that order, `ops`/`roster`
     * omitted when empty and `match_number` when null (`omitempty`).
     */
    fun toJson(): ByteArray = ApprovalJson.obj(
        "credential" to credential,
        "ops" to ops.ifEmpty { null },
        "roster" to roster.ifEmpty { null },
        "sig" to sig,
        "match_number" to matchNumber?.toLong(),
    )
}

/**
 * The body of `POST /approval/fetch`: the tuple's [handle], the broker's [nonce], the
 * fetcher's [credential] and presented [ops] / [roster] (authenticated through
 * `CheckOrg` with the broker's own org), and the [proof] over
 * [Approval.fetchPreimage]. Go `approval.FetchRequest`.
 */
class FetchRequest(
    val handle: Handle,
    val nonce: FetchNonce,
    val credential: String,
    val ops: List<String>,
    val roster: List<String>,
    val proof: String,
) {
    /**
     * Go's `json.Marshal` of `FetchRequest`: `{"handle","nonce","credential","ops","roster","proof"}`,
     * `ops`/`roster` omitted when empty.
     */
    fun toJson(): ByteArray = ApprovalJson.obj(
        "handle" to handle.toString(),
        "nonce" to nonce.toString(),
        "credential" to credential,
        "ops" to ops.ifEmpty { null },
        "roster" to roster.ifEmpty { null },
        "proof" to proof,
    )
}

/**
 * A challenge as the broker sends it to the approver: no match-number field (ADR-0006).
 * [nonce] and [actionDigest] are unpadded base64url, times and [ttl] in seconds;
 * [candidates] is null when the body had none (a Go nil slice). Go `approval.FetchedChallenge`.
 */
@Suppress("LongParameterList") // Go's struct, field for field
class FetchedChallenge(
    val id: String,
    val nonce: String,
    val audience: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val candidates: List<Long>?,
    val actionDigest: String,
    val resource: String,
    val ttl: Long,
)

/** An action on the wire; [params] is unpadded base64url, `""` for none. Go `approval.WireAction`. */
class WireAction(val kind: String, val resource: String, val summary: String, val params: String)

/** What [FetchResponse.open] yields: the checked challenge (match number 0) and its action. */
class OpenedApproval(val challenge: Challenge, val action: Action)

/**
 * The body of a successful `POST /approval/fetch`: the challenge without its match number,
 * and the stored action. Go `approval.FetchResponse`.
 */
class FetchResponse(val challenge: FetchedChallenge, val action: WireAction) {

    /** Go's `json.Marshal` of the response (a test broker's answer). */
    fun toJson(): ByteArray {
        val c = challenge
        val ch = ApprovalJson.obj(
            "id" to c.id,
            "nonce" to c.nonce,
            "audience" to c.audience,
            "issued_at" to c.issuedAt,
            "expires_at" to c.expiresAt,
            "candidates" to (c.candidates ?: ApprovalJson.NIL),
            "action_digest" to c.actionDigest,
            "resource" to c.resource,
            "ttl" to c.ttl,
        )
        val a = ApprovalJson.obj(
            "kind" to action.kind,
            "resource" to action.resource,
            "summary" to action.summary,
            "params" to action.params,
        )
        return ApprovalJson.obj("challenge" to ApprovalJson.Raw(ch), "action" to ApprovalJson.Raw(a))
    }

    /**
     * The approver's reading of the answer, in Go `FetchResponse.Open`'s order: the
     * challenge nonce and the action digest must be canonical unpadded base64url of 32
     * bytes, the candidates [Approval.MATCH_CANDIDATE_COUNT] distinct numbers in
     * `[0, 100)`, the ttl in `[0, 1 h]` ([Failure.TTL_TOO_LONG]), the challenge well
     * formed ([Challenge.preimage], with match number 0), the params canonical base64url,
     * and the action well formed and recomputing — over exactly the fetched bytes, never
     * canonicalised again — to the challenge's digest ([Failure.DIGEST_MISMATCH]) and
     * naming its resource ([Failure.RESOURCE_MISMATCH]). Only then may the approver
     * display [Action.summary] and [Action.resource], and sign.
     */
    @Throws(Exception::class)
    fun open(): OpenedApproval {
        val fc = challenge
        val nonce = Approval.decodeCanonical(fc.nonce)?.takeIf { it.size == Approval.NONCE_LEN }
            ?: Approval.fail(Failure.MALFORMED, "challenge nonce")
        val digest = Approval.decodeCanonical(fc.actionDigest)?.takeIf { it.size == Approval.DIGEST_LEN }
            ?: Approval.fail(Failure.MALFORMED, "action digest")
        val candidates = checkCandidates(fc.candidates)
        if (fc.ttl < 0 || fc.ttl > Approval.MAX_APPROVAL_TTL_SECONDS) {
            Approval.fail(Failure.TTL_TOO_LONG, "ttl ${fc.ttl}s")
        }
        val c = Challenge(
            id = fc.id,
            nonce = nonce,
            audience = fc.audience,
            issuedAt = fc.issuedAt,
            expiresAt = fc.expiresAt,
            matchNumber = 0,
            candidates = candidates,
            actionDigest = digest,
            resource = fc.resource,
            ttlSeconds = fc.ttl,
        )
        c.preimage()
        val params = Approval.decodeCanonical(action.params) ?: Approval.fail(Failure.MALFORMED, "action params")
        val a = Action(action.kind, action.resource, action.summary, params)
        c.requireMatches(a)
        return OpenedApproval(c, a)
    }

    companion object {
        /** A response body larger than this is refused unparsed (a client-side bound; params alone are ≤ 64 KiB). */
        const val MAX_BODY_LEN = 1 shl 20

        private val TOP = listOf("challenge", "action")
        private val CHALLENGE_FIELDS = listOf(
            "id", "nonce", "audience", "issued_at", "expires_at", "candidates", "action_digest", "resource", "ttl",
        )
        private val ACTION_FIELDS = listOf("kind", "resource", "summary", "params")

        /**
         * Decodes a fetch answer as Go's `json.Unmarshal` into `FetchResponse` does:
         * members matched to fields exactly or case-insensitively (Go's fold), unknown
         * members (a `match_number` included) ignored, a repeated object member merged into
         * the same struct, `null` leaving a field as it was (a slice nil), and any value of
         * the wrong JSON type — or an integer that is not an int64 literal — refused
         * ([Failure.MALFORMED]), as Go's `UnmarshalTypeError` is. Invalid UTF-8 inside a
         * string becomes U+FFFD per byte, as Go decodes it. The reader is iterative.
         */
        @Throws(Exception::class)
        fun parse(body: ByteArray): FetchResponse {
            if (body.size > MAX_BODY_LEN) Approval.fail(Failure.MALFORMED, "a ${body.size}-byte response")
            val root = GoJson.parse(ApprovalJson.goUtf8(body)) ?: Approval.fail(Failure.MALFORMED, "not JSON")
            val c = ChallengeBuilder()
            val a = ActionBuilder()
            try {
                ApprovalJson.members(root, TOP) { f, v ->
                    when (f) {
                        "challenge" -> ApprovalJson.members(v, CHALLENGE_FIELDS) { cf, cv -> c.set(cf, cv) }
                        else -> ApprovalJson.members(v, ACTION_FIELDS) { af, av -> a.set(af, av) }
                    }
                }
            } catch (_: ApprovalJson.TypeError) {
                Approval.fail(Failure.MALFORMED, "a member has the wrong JSON type")
            }
            return FetchResponse(
                FetchedChallenge(
                    c.id, c.nonce, c.audience, c.issuedAt, c.expiresAt, c.candidates, c.actionDigest,
                    c.resource, c.ttl,
                ),
                WireAction(a.kind, a.resource, a.summary, a.params),
            )
        }

        /** Go `checkCandidates`: exactly three distinct numbers in `[0, 100)`. */
        private fun checkCandidates(cs: List<Long>?): List<Int> {
            val list = cs.orEmpty()
            if (list.size != Approval.MATCH_CANDIDATE_COUNT) {
                Approval.fail(Failure.MALFORMED, "candidates: ${list.size}, want ${Approval.MATCH_CANDIDATE_COUNT}")
            }
            if (list.any { it !in 0 until Approval.MATCH_NUMBER_BOUND } || list.toSet().size != list.size) {
                Approval.fail(Failure.MALFORMED, "candidates: out of range or repeated")
            }
            return list.map { it.toInt() }
        }
    }

    private class ChallengeBuilder {
        var id = ""
        var nonce = ""
        var audience = ""
        var issuedAt = 0L
        var expiresAt = 0L
        var candidates: List<Long>? = null
        var actionDigest = ""
        var resource = ""
        var ttl = 0L

        fun set(f: String, v: GoJson.Node) {
            when (f) {
                "id" -> id = ApprovalJson.str(v, id)
                "nonce" -> nonce = ApprovalJson.str(v, nonce)
                "audience" -> audience = ApprovalJson.str(v, audience)
                "issued_at" -> issuedAt = ApprovalJson.long(v, issuedAt)
                "expires_at" -> expiresAt = ApprovalJson.long(v, expiresAt)
                "candidates" -> candidates = ApprovalJson.longs(v)
                "action_digest" -> actionDigest = ApprovalJson.str(v, actionDigest)
                "resource" -> resource = ApprovalJson.str(v, resource)
                else -> ttl = ApprovalJson.long(v, ttl)
            }
        }
    }

    private class ActionBuilder {
        var kind = ""
        var resource = ""
        var summary = ""
        var params = ""

        fun set(f: String, v: GoJson.Node) {
            when (f) {
                "kind" -> kind = ApprovalJson.str(v, kind)
                "resource" -> resource = ApprovalJson.str(v, resource)
                "summary" -> summary = ApprovalJson.str(v, summary)
                else -> params = ApprovalJson.str(v, params)
            }
        }
    }
}

/** The answer to `POST /approval/fetch-nonce`: `{"nonce"}`. */
internal object FetchNonceResponse {
    private val FIELDS = listOf("nonce")

    /**
     * Go's `json.Unmarshal` into `FetchNonceResponse`, then [Approval.parseFetchNonce]:
     * a body that does not decode, or a nonce that is not 32 canonical non-zero bytes, is
     * refused ([Failure.MALFORMED] / [Failure.FETCH_NONCE_SPENT]).
     */
    @Throws(Exception::class)
    fun parse(body: ByteArray): FetchNonce {
        if (body.size > FetchResponse.MAX_BODY_LEN) Approval.fail(Failure.MALFORMED, "a ${body.size}-byte response")
        val root = GoJson.parse(ApprovalJson.goUtf8(body)) ?: Approval.fail(Failure.MALFORMED, "not JSON")
        var nonce = ""
        try {
            ApprovalJson.members(root, FIELDS) { _, v -> nonce = ApprovalJson.str(v, nonce) }
        } catch (_: ApprovalJson.TypeError) {
            Approval.fail(Failure.MALFORMED, "nonce is not a string")
        }
        return Approval.parseFetchNonce(nonce)
    }
}

/**
 * The JSON the approval bodies need, with Go `encoding/json` semantics: [obj] renders a
 * struct as `json.Marshal` does (compact, fields in order, strings via
 * [GoJson.appendString]); [members]/[str]/[long]/[longs] decode as `json.Unmarshal` into
 * a struct does; [goUtf8] decodes bytes as Go reads a string.
 */
internal object ApprovalJson {
    /** A field rendered as `null` (a nil Go slice), as opposed to a Kotlin null, which omits it. */
    object NIL

    /** Pre-rendered JSON. */
    class Raw(val json: ByteArray)

    /** A JSON value of the wrong type for its field (Go's `UnmarshalTypeError`). */
    class TypeError : Exception()

    /** Values: String, Long, List of String or Long, [Raw], [NIL]; a null value omits the field. */
    fun obj(vararg fields: Pair<String, Any?>): ByteArray {
        val sb = StringBuilder("{")
        var first = true
        for ((k, v) in fields) {
            if (v == null) continue
            if (!first) sb.append(',')
            first = false
            GoJson.appendString(sb, k)
            sb.append(':')
            when (v) {
                is String -> GoJson.appendString(sb, v)

                is Long -> sb.append(v)

                is Raw -> sb.append(v.json.decodeToString())

                NIL -> sb.append("null")

                is List<*> -> {
                    sb.append('[')
                    v.forEachIndexed { i, e ->
                        if (i > 0) sb.append(',')
                        if (e is String) GoJson.appendString(sb, e) else sb.append(e as Long)
                    }
                    sb.append(']')
                }

                else -> error("unsupported JSON value ${v::class}")
            }
        }
        return sb.append('}').toString().encodeToByteArray()
    }

    /**
     * Go's struct decode of [node] over [fields]: `null` is a no-op, an object's members
     * go to the field named exactly, else to the first that folds to it (Go's
     * case-insensitive match), else nowhere; anything else is [TypeError].
     */
    fun members(node: GoJson.Node, fields: List<String>, set: (String, GoJson.Node) -> Unit) {
        when (node) {
            GoJson.Null -> Unit

            is GoJson.Obj -> for ((k, v) in node.members) {
                val f = fields.firstOrNull { it == k } ?: fields.firstOrNull { GoJson.foldsTo(k, it) }
                if (f != null) set(f, v)
            }

            else -> throw TypeError()
        }
    }

    /** A string field: `null` keeps [cur]. */
    fun str(node: GoJson.Node, cur: String): String = when (node) {
        is GoJson.Str -> node.value
        GoJson.Null -> cur
        else -> throw TypeError()
    }

    /** An int64 field (Go `strconv.ParseInt` of the literal): `null` keeps [cur]. */
    fun long(node: GoJson.Node, cur: Long): Long = when (node) {
        is GoJson.Num -> node.text.toLongOrNull() ?: throw TypeError()
        GoJson.Null -> cur
        else -> throw TypeError()
    }

    /** An `[]int` field: `null` is a nil slice; a `null` element is 0, as Go leaves it. */
    fun longs(node: GoJson.Node): List<Long>? = when (node) {
        GoJson.Null -> null
        is GoJson.Arr -> node.items.map { long(it, 0L) }
        else -> throw TypeError()
    }

    /** [GoJson.decodeUtf8]: [b] as Go's JSON decoder reads a string. */
    fun goUtf8(b: ByteArray): String = GoJson.decodeUtf8(b)
}
