package one.rarebit.voidwhichbinds.approval

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MemberKey
import one.rarebit.voidwhichbinds.PushPing
import one.rarebit.voidwhichbinds.VoidbindDeepLink
import one.rarebit.voidwhichbinds.WebAuthn
import one.rarebit.voidwhichbinds.WebAuthnPolicy
import one.rarebit.voidwhichbinds.WebAuthnRp
import one.rarebit.voidwhichbinds.approval.Approval.ApprovalException
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The cross-implementation PARITY suite for the approver's side of action approval
 * (void-which-binds-go ADR-0019, G9a): Go's golden vectors,
 * `testvectors/vectors/approval/` (pinned by `VOID_WHICH_BINDS_GO_REF`), copied verbatim
 * into `src/jvmTest/resources/vectors/approval/`. Per the vectors' README:
 *
 * - every action digest (or its `malformed` refusal), challenge preimage (or its refusal,
 *   with the hand-framed bytes), WebAuthn challenge and fetch preimage is recomputed byte
 *   for byte, through the approver's entry points ([Approval.passkeyChallenge],
 *   [Approval.fetchPasskeyChallenge]) where they apply;
 * - every tuple is encoded / parsed exactly ([Approval.parseApprove], and the push and
 *   deep-link wrappers agree);
 * - every `ed25519` mint is re-signed from its seed byte for byte, and every approval and
 *   fetch proof the approver could have made is re-minted through
 *   [Approval.signAssertionWith] / [Approval.signFetchProofWith]; every `webauthn` mint
 *   is verified (verify-only) over its domain's challenge;
 * - every `response` round-trips through [FetchResponse.parse] / [FetchResponse.toJson]
 *   and [FetchResponse.open] recomputes its digest;
 * - each approval and fetch verdict is reproduced by [GoVerifier], a test-side mirror of
 *   Go's `CheckAssertion`/`VerifyAssertion`/`VerifyFetchProof` built on this library's
 *   preimages and parsers (the verifier itself is the broker's, and not shipped here).
 */
@Suppress("UNCHECKED_CAST", "ReturnCount", "ComplexCondition")
class ApprovalVectorTest {
    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/approval") ?: error("vectors/approval missing")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty()
            .map { it.name.removeSuffix(".json") }.sorted()
            .also { check(it.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS vectors, found ${it.size}" } }
    }

    private fun load(name: String): Map<String, Any> {
        val raw = javaClass.getResourceAsStream("/vectors/approval/$name.json")!!.readBytes().decodeToString()
        return MiniJson.parseObject(raw).also { assertEquals(name, it["name"], "file stem must equal its name") }
    }

    private fun list(v: Map<String, Any>, k: String): List<Map<String, Any>> =
        (v[k] as? List<Map<String, Any>>).orEmpty()

    private class Key(val id: String, val seed: ByteArray?) {
        val pub: ByteArray? = seed?.let { Ed25519Group.publicKeyFromSeed(it) }
        val signer: Ed25519Signer? = seed?.let { s -> Ed25519Signer { Ed25519Engine.sign(s, it) } }
    }

    private fun keys(v: Map<String, Any>): Map<String, Key> =
        (v["keys"] as Map<String, Map<String, Any>>).mapValues { (label, k) ->
            val seed = (k["sign_seed"] as String?)?.let(Hex::decode)
            val key = Key(k["id"] as String, seed)
            key.pub?.let { assertEquals(key.id, KeyRef.ed25519(it).render(), "key $label: id does not match its seed") }
            key
        }

    private fun policy(v: Map<String, Any>, synced: Boolean) = WebAuthnPolicy(
        list(v, "webauthn_rps").map { WebAuthnRp(it["rp_id"] as String, it["origins"] as List<String>) },
        allowSynced = synced,
    )

    private fun action(m: Map<String, Any>) =
        Action(m["kind"] as String, m["resource"] as String, m["summary"] as String, Hex.decode(m["params"] as String))

    private fun challenge(m: Map<String, Any>) = Challenge(
        id = m["id"] as String,
        nonce = Hex.decode(m["nonce"] as String),
        audience = m["audience"] as String,
        issuedAt = m["issued_at"] as Long,
        expiresAt = m["expires_at"] as Long,
        matchNumber = (m["match_number"] as Long).toInt(),
        candidates = (m["candidates"] as List<Long>).map { it.toInt() },
        actionDigest = Hex.decode(m["action_digest"] as String),
        resource = m["resource"] as String,
        ttlSeconds = m["ttl"] as Long,
    )

    /** Go's `handFrame`: the plain framing of a challenge's fields, with no checks. */
    private fun handFrame(c: Challenge): ByteArray = Frames()
        .add(Approval.DOMAIN_CHALLENGE.encodeToByteArray())
        .add(c.id.encodeToByteArray())
        .add(c.nonce)
        .add(c.audience.encodeToByteArray())
        .add(Frames.u64(c.expiresAt))
        .add(Frames.u64(c.matchNumber.toLong()))
        .add(c.actionDigest)
        .add(c.resource.encodeToByteArray())
        .add(Frames.u64(c.ttlSeconds))
        .bytes()

    private fun failureWord(block: () -> Unit): String = try {
        block()
        "ok"
    } catch (e: ApprovalException) {
        e.reason
    }

    private class Ctx(
        val name: String,
        val v: Map<String, Any>,
        val keys: Map<String, Key>,
        val actions: Map<String, Action>,
        val challenges: Map<String, Challenge>,
        val mints: List<Map<String, Any>>,
    )

    private val counts = HashMap<String, Int>()

    private fun count(what: String) {
        counts.merge(what, 1, Int::plus)
    }

    @Test
    fun everyVectorReplays() {
        for (name in cases) replay(name)
        for (
        what in listOf(
            "action", "action-refused", "challenge", "challenge-refused", "passkey-challenge", "fetch-preimage",
            "tuple-ok", "tuple-refused", "mint-ed25519", "mint-webauthn", "approval", "approval-resigned",
            "fetch", "fetch-resigned", "response", "raw", "refusal",
        )
        ) {
            assertTrue((counts[what] ?: 0) > 0, "nothing replayed for $what: $counts")
        }
    }

    private fun replay(name: String) {
        val v = load(name)
        val ks = keys(v)
        val acts = LinkedHashMap<String, Action>()
        for (a in list(v, "actions")) {
            val label = "$name/action ${a["label"]}"
            val act = action(a)
            val err = a["error"] as String?
            if (err != null) {
                assertEquals(err, failureWord { act.digest() }, label)
                count("action-refused")
            } else {
                assertEquals(a["digest"], Hex.encode(act.digest()), label)
                count("action")
            }
            acts[a["label"] as String] = act
        }
        val chs = LinkedHashMap<String, Challenge>()
        for (c in list(v, "challenges")) chs[c["label"] as String] = replayChallenge(name, c, acts)
        val ctx = Ctx(name, v, ks, acts, chs, list(v, "mints"))
        list(v, "fetch_preimages").forEach { replayFetchPreimage(name, it) }
        list(v, "tuples").forEach { replayTuple(name, it) }
        ctx.mints.forEach { replayMint(ctx, it) }
        list(v, "approvals").forEach { replayApproval(ctx, it) }
        list(v, "fetches").forEach { replayFetch(ctx, it) }
        list(v, "raw").forEach { replayRaw(ctx, it) }
        (v["fetch_refusal"] as Map<String, Any>?)?.let {
            assertEquals(Approval.FETCH_REFUSAL_STATUS.toLong(), it["status"], "$name: refusal status")
            assertEquals(Approval.FETCH_REFUSAL_BODY, it["body"], "$name: refusal body")
            count("refusal")
        }
    }

    private fun replayChallenge(name: String, m: Map<String, Any>, acts: Map<String, Action>): Challenge {
        val label = "$name/challenge ${m["label"]}"
        val c = challenge(m)
        val err = m["error"] as String?
        if (err != null) {
            assertEquals(err, failureWord { c.preimage() }, label)
            if (m["mint_error"] == "ttl_too_long") {
                val e = runCatching { c.preimage() }.exceptionOrNull() as ApprovalException
                assertEquals(Approval.Failure.TTL_TOO_LONG, e.failure, "$label: ttl_too_long")
            }
            assertEquals(m["preimage"], Hex.encode(handFrame(c)), "$label: hand framing")
            count("challenge-refused")
            return c
        }
        val pre = c.preimage()
        assertEquals(m["preimage"], Hex.encode(pre), "$label: preimage")
        assertContentEquals(handFrame(c), pre, "$label: hand framing")
        assertEquals(m["webauthn_challenge"], Hex.encode(WebAuthn.challenge(Approval.DOMAIN_CHALLENGE, pre)), label)
        count("challenge")
        val a = acts[m["action"] as String?]
        if (a != null && failureWord { c.requireMatches(a) } == "ok" && c.matchNumber in c.candidates) {
            // The approver's entry point gives the same challenge for the true number.
            assertEquals(
                m["webauthn_challenge"],
                Hex.encode(Approval.passkeyChallenge(c, a, c.matchNumber)),
                "$label: passkeyChallenge",
            )
            count("passkey-challenge")
        }
        return c
    }

    private fun replayFetchPreimage(name: String, m: Map<String, Any>) {
        val label = "$name/fetch preimage ${m["label"]}"
        val h = Approval.parseHandle(m["handle"] as String)
        val n = Approval.parseFetchNonce(m["nonce"] as String)
        assertEquals(m["handle"], h.toString(), label)
        assertEquals(m["nonce"], n.toString(), label)
        val audience = m["audience"] as String
        val pre = Approval.fetchPreimage(audience, h, n)
        assertEquals(m["preimage"], Hex.encode(pre), label)
        val hand = Frames().add(Approval.DOMAIN_FETCH.encodeToByteArray()).add(audience.encodeToByteArray())
            .add(h.bytes).add(n.bytes).bytes()
        assertContentEquals(hand, pre, "$label: hand framing")
        assertEquals(m["webauthn_challenge"], Hex.encode(Approval.fetchPasskeyChallenge(audience, h, n)), label)
        count("fetch-preimage")
    }

    private fun replayTuple(name: String, m: Map<String, Any>) {
        val tuple = m["tuple"] as String
        val label = "$name/tuple $tuple"
        (m["handle"] as String?)?.let { assertEquals(tuple, Approval.encodeApprove(Approval.parseHandle(it)), label) }
        val got = failureWord { Approval.parseApprove(tuple) }
        assertEquals(m["expect"], got, label)
        val h = Approval.parseApproveOrNull(tuple)
        assertEquals(h, PushPing.parseApproveOrNull(tuple), "$label: push")
        assertEquals(h, VoidbindDeepLink.parseApproveOrNull(tuple), "$label: deep link")
        if (got == "ok") {
            assertEquals(m["handle"], h.toString(), label)
            count("tuple-ok")
        } else {
            assertNull(h, label)
            count("tuple-refused")
        }
    }

    private fun replayMint(ctx: Ctx, m: Map<String, Any>) {
        val label = "${ctx.name}/mint ${m["label"]}"
        val body = Hex.decode(m["body"] as String)
        val k = ctx.keys.getValue(m["signer"] as String)
        when (m["kind"]) {
            "ed25519" -> {
                assertEquals(m["sig"], Base64Url.encode(Ed25519Engine.sign(k.seed!!, body)), "$label: re-sign")
                count("mint-ed25519")
            }

            "webauthn" -> {
                val env = Base64Url.decode(m["sig"] as String)
                MemberKey.parse(k.id).verifyBody(m["domain"] as String, body, env, policy(ctx.v, synced = true))
                count("mint-webauthn")
            }

            else -> error("$label: unknown mint kind ${m["kind"]}")
        }
    }

    private fun replayApproval(ctx: Ctx, m: Map<String, Any>) {
        val label = "${ctx.name}/approval ${m["label"]}"
        val c = ctx.challenges.getValue(m["challenge"] as String)
        val a = ctx.actions.getValue(m["action"] as String)
        val asr = m["assertion"] as Map<String, Any>
        val sig = asr["sig"] as String
        val chosen = (asr["match_number"] as Long?)?.toInt()
        val approver = ctx.keys.getValue(m["approver"] as String)
        val got = GoVerifier.approval(
            c,
            a,
            asr["credential"] as String,
            sig,
            chosen,
            approver.id,
            policy(ctx.v, m["allow_synced"] as Boolean),
            m["now"] as Long,
        )
        assertEquals(m["expect"], got, label)
        count("approval")
        // Re-mint the assertion through the approver's entry point wherever it could have made it.
        if (approver.signer == null || chosen == null || chosen !in c.candidates || asr["credential"] == "") return
        if (failureWord { c.requireMatches(a) } != "ok") return
        val pre = runCatching { c.withMatchNumber(chosen).preimage() }.getOrNull() ?: return
        val made = ctx.mints.any {
            it["kind"] == "ed25519" && it["signer"] == m["approver"] && it["sig"] == sig &&
                it["body"] == Hex.encode(pre)
        }
        if (!made) return
        val re = Approval.signAssertionWith(approver.signer, approver.pub!!, c, a, chosen, asr["credential"] as String)
        assertEquals(goJson(asr), re.toJson().decodeToString(), "$label: signAssertionWith")
        count("approval-resigned")
    }

    private fun replayFetch(ctx: Ctx, m: Map<String, Any>) {
        val label = "${ctx.name}/fetch ${m["label"]}"
        val req = m["request"] as Map<String, Any>
        val audience = m["audience"] as String
        val fetcher = ctx.keys.getValue(m["fetcher"] as String)
        val got = GoVerifier.fetch(
            req["handle"] as String, req["nonce"] as String, req["credential"] as String, req["proof"] as String,
            audience, fetcher.id, policy(ctx.v, m["allow_synced"] as Boolean), m["nonce_issued_at"] as Long,
            m["now"] as Long,
        )
        assertEquals(m["expect"], got, label)
        count("fetch")
        m["response"]?.let { replayResponse(ctx, label, it as Map<String, Any>, m["response_of"] as Map<String, Any>) }
        // The request body and an Ed25519 proof, re-made through the approver's entry points.
        val h = Approval.parseApproveOrNull(Approval.APPROVE_TUPLE_PREFIX + req["handle"]) ?: return
        val n = runCatching { Approval.parseFetchNonce(req["nonce"] as String) }.getOrNull() ?: return
        val proof = req["proof"] as String
        val body = FetchRequest(h, n, req["credential"] as String, emptyList(), emptyList(), proof).toJson()
        assertEquals(goJson(req), body.decodeToString(), "$label: request body")
        if (fetcher.signer == null) return
        val pre = Hex.encode(Approval.fetchPreimage(audience, h, n))
        val made = ctx.mints.any {
            it["kind"] == "ed25519" && it["signer"] == m["fetcher"] && it["sig"] == proof && it["body"] == pre
        }
        if (!made) return
        assertEquals(proof, Approval.signFetchProofWith(fetcher.signer, fetcher.pub!!, audience, h, n), label)
        count("fetch-resigned")
    }

    private fun replayResponse(ctx: Ctx, label: String, resp: Map<String, Any>, of: Map<String, Any>) {
        val wire = goJson(resp)
        val parsed = FetchResponse.parse(wire.encodeToByteArray())
        assertEquals(wire, parsed.toJson().decodeToString(), "$label: response round trip")
        val opened = parsed.open()
        val stored = ctx.challenges.getValue(of["challenge"] as String)
        assertContentEquals(
            handFrame(stored.withMatchNumber(0)),
            opened.challenge.preimage(),
            "$label: opened challenge",
        )
        assertEquals(stored.candidates, opened.challenge.candidates, "$label: candidates")
        assertEquals(stored.issuedAt, opened.challenge.issuedAt, "$label: issued_at")
        assertEquals(ctx.actions.getValue(of["action"] as String), opened.action, "$label: opened action")
        assertContentEquals(opened.challenge.actionDigest, opened.action.digest(), "$label: digest recomputes")
        count("response")
    }

    private fun replayRaw(ctx: Ctx, m: Map<String, Any>) {
        val label = "${ctx.name}/raw ${m["label"]}"
        val mint = ctx.mints.first { it["label"] == m["mint"] }
        val key = MemberKey.parse(ctx.keys.getValue(m["key"] as String).id)
        val domain = (m["domain"] as String).ifEmpty { "unused-for-ed25519" }
        val err = runCatching {
            key.verifyBody(
                domain,
                Hex.decode(m["body"] as String),
                Base64Url.decode(mint["sig"] as String),
                policy(ctx.v, synced = false),
            )
        }.exceptionOrNull()
        assertEquals(m["expect"], MemberKey.reason(err), label)
        count("raw")
    }

    /** Compact JSON of a vector object, in its document order (Go's struct order). */
    private fun goJson(m: Map<String, Any>): String = MiniJson.encodeObject(pairs(m))

    private fun pairs(m: Map<String, Any>): List<Pair<String, Any>> =
        m.entries.map { (k, v) -> k to if (v is Map<*, *>) pairs(v as Map<String, Any>) else v }

    private companion object {
        const val MIN_VECTORS = 28
    }
}

/**
 * A test-side mirror of void-which-binds-go's verifier checks (`approval.CheckAssertion`,
 * `VerifyAssertion`, `VerifyFetchProof`, `ReasonFor`), in Go's order, over this library's
 * preimages and parsers, so each vector's verdict checks them end to end.
 */
private object GoVerifier {
    private const val MAX_SIG_LEN = 22 shl 10

    @Suppress("LongParameterList", "ReturnCount")
    fun approval(
        c: Challenge,
        stored: Action,
        credential: String,
        sig: String,
        chosen: Int?,
        key: String,
        pol: WebAuthnPolicy,
        now: Long,
    ): String {
        val pre = try {
            c.preimage()
        } catch (e: ApprovalException) {
            return e.reason
        }
        if (now >= c.expiresAt) return "challenge_expired"
        if (credential.isEmpty() || sig.isEmpty() || chosen == null) return "malformed"
        if (chosen != c.matchNumber) return "number_mismatch"
        try {
            c.requireMatches(stored)
        } catch (e: ApprovalException) {
            return e.reason
        }
        return when (val w = memberSig(Approval.DOMAIN_CHALLENGE, pre, sig, key, pol)) {
            null -> "ok"
            "bad_signature", "malformed" -> "bad_assertion"
            else -> w
        }
    }

    @Suppress("LongParameterList", "ReturnCount")
    fun fetch(
        handle: String,
        nonce: String,
        credential: String,
        proof: String,
        audience: String,
        key: String,
        pol: WebAuthnPolicy,
        issuedAt: Long,
        now: Long,
    ): String {
        val n = try {
            Approval.parseFetchNonce(nonce)
        } catch (e: ApprovalException) {
            return e.reason
        }
        if (now < issuedAt || now >= issuedAt + Approval.FETCH_NONCE_TTL_SECONDS) return "fetch_nonce_spent"
        val h = try {
            Approval.parseHandle(handle)
        } catch (e: ApprovalException) {
            return e.reason
        }
        if (credential.isEmpty() || proof.isEmpty()) return "fetch_unauthenticated"
        val pre = runCatching { Approval.fetchPreimage(audience, h, n) }.getOrNull() ?: return "bad_fetch_proof"
        return if (memberSig(Approval.DOMAIN_FETCH, pre, proof, key, pol) == null) "ok" else "bad_fetch_proof"
    }

    /** Go `verifyMemberSig`: null when it verifies, else ADR-0018's word (`malformed` for a bad encoding). */
    @Suppress("ReturnCount")
    private fun memberSig(domain: String, body: ByteArray, sig: String, key: String, pol: WebAuthnPolicy): String? {
        if (sig.isEmpty() || sig.length > MAX_SIG_LEN) return "malformed"
        val raw = Approval.decodeCanonical(sig) ?: return "malformed"
        val err = runCatching { MemberKey.parse(key).verifyBody(domain, body, raw, pol) }.exceptionOrNull()
        return if (err == null) null else MemberKey.reason(err)
    }
}
