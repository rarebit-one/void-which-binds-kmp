package one.rarebit.voidwhichbinds.approval

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.MemberKey
import one.rarebit.voidwhichbinds.PushPing
import one.rarebit.voidwhichbinds.WebAuthnPolicy
import one.rarebit.voidwhichbinds.approval.Approval.ApprovalException
import one.rarebit.voidwhichbinds.approval.Approval.Failure
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.ApprovalClient
import one.rarebit.voidwhichbinds.net.ApprovalFetchRefusedException
import one.rarebit.voidwhichbinds.net.ApprovalHttpException
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The approver's side of action approval beyond the Go vectors (ApprovalVectorTest):
 * the action grammar's edges, the Go-struct reading of a fetch answer (fold, merge,
 * type errors, canonical base64url), [FetchResponse.open]'s refusals, the number gate,
 * and [ApprovalClient] against a fake broker. Signature bytes are not compared here
 * (CryptoKit signs randomly); signatures are verified instead.
 */
class ApprovalTest {
    private val seed = ByteArray(32) { (it + 1).toByte() }
    private val pub = Ed25519Group.publicKeyFromSeed(seed)
    private val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private val key = MemberKey.parse(
        "ed25519:" + pub.joinToString("") {
            (it.toInt() and 0xFF).toString(16).padStart(2, '0')
        },
    )

    private val action =
        Action("deploy", "do:team/ops", "Deploy web to production", "{\"env\":\"prod\"}".encodeToByteArray())
    private val audience = "https://broker.example"
    private val handle = Approval.parseHandle(Base64Url.encode(ByteArray(32) { 7 }))
    private val fetchNonce = Approval.parseFetchNonce(Base64Url.encode(ByteArray(32) { 9 }))

    private fun wire(
        a: Action = action,
        digest: ByteArray = action.digest(),
        resource: String = action.resource,
        candidates: List<Long>? = listOf(17, 42, 86),
        ttl: Long = 600,
    ) = FetchResponse(
        FetchedChallenge(
            id = "c6e736e7b62631430edbf305c4113304",
            nonce = Base64Url.encode(ByteArray(32) { 3 }),
            audience = audience,
            issuedAt = 1_791_028_800,
            expiresAt = 1_791_028_920,
            candidates = candidates,
            actionDigest = Base64Url.encode(digest),
            resource = resource,
            ttl = ttl,
        ),
        WireAction(a.kind, a.resource, a.summary, Base64Url.encode(a.params)),
    )

    private fun failure(block: () -> Unit): Failure = assertFailsWith<ApprovalException> { block() }.failure

    // --- the action grammar ------------------------------------------------------

    @Test
    fun summaryGrammarMatchesGo() {
        fun ok(s: String) = Action("deploy", "do:team/ops", s, ByteArray(0)).digest()
        fun refused(s: String) = assertEquals(Failure.MALFORMED, failure { ok(s) }, "summary ${s.map { it.code }}")
        ok("Supprimer l’équipe « ops » — 東京 🚀")
        ok("a".repeat(Approval.MAX_SUMMARY_LEN))
        ok("x y") // a line separator is Zl, not Cc: Go's unicode.IsControl does not refuse it
        ok("x y")
        refused("")
        refused("a".repeat(Approval.MAX_SUMMARY_LEN + 1))
        refused("é".repeat(Approval.MAX_SUMMARY_LEN / 2 + 1)) // 1026 bytes in 513 chars
        refused("tab\there")
        refused("del\u007F")
        refused("c1\u0085")
        refused("lone \uD800 surrogate")
        for (bidi in listOf('؜', '‎', '‏', '‪', '‮', '⁦', '⁩')) refused("x${bidi}y")
    }

    @Test
    fun kindResourceAndParamsGrammar() {
        fun act(kind: String = "deploy", resource: String = "do:team/ops", params: Int = 0) =
            Action(kind, resource, "s", ByteArray(params))
        act(kind = "a").digest()
        act(kind = "a" + "b-9".repeat(10) + "c").digest()
        act(params = Approval.MAX_PARAMS_LEN).digest()
        for (bad in listOf("", "Deploy", "1deploy", "-x", "dé", "a".repeat(33), "de ploy")) {
            assertEquals(Failure.MALFORMED, failure { act(kind = bad).digest() }, bad)
        }
        assertEquals(Failure.MALFORMED, failure { act(resource = "do:Team").digest() })
        assertEquals(Failure.MALFORMED, failure { act(params = Approval.MAX_PARAMS_LEN + 1).digest() })
    }

    // --- the tuple ---------------------------------------------------------------

    @Test
    fun theApproveTupleIsExactAndCarriesOnlyTheHandle() {
        val tuple = Approval.encodeApprove(handle)
        assertEquals("void-which-binds:approve?h=$handle", tuple)
        assertEquals(handle, PushPing.parseApproveOrNull(tuple))
        assertNull(PushPing.parseApproveOrNull("$tuple\n"), "nothing is trimmed")
        assertNull(PushPing.parseApproveOrNull(LoginQr.encode("https://rp.example", "abc")))
        assertNull(PushPing.parseOrNull(tuple), "an approve wake is not a login ping")
        assertEquals(Failure.UNKNOWN_HANDLE, failure { Approval.parseApprove(tuple.dropLast(1) + "\n") })
    }

    @Test
    fun handlesAndNoncesAreCanonical() {
        val s = handle.toString()
        // The last character's two low bits are padding; setting one is a second spelling of the same bytes.
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val alt = s.dropLast(1) + alphabet[alphabet.indexOf(s.last()) xor 1]
        assertContentEquals(handle.bytes, Base64Url.decode(alt))
        assertEquals(Failure.UNKNOWN_HANDLE, failure { Approval.parseHandle(alt) })
        assertEquals(
            Failure.UNKNOWN_HANDLE,
            failure {
                Approval.parseHandle(s.substring(0, 20) + "\r\n" + s.substring(22))
            },
        )
        assertEquals(Failure.UNKNOWN_HANDLE, failure { Approval.parseHandle(Base64Url.encode(ByteArray(32))) })
        assertEquals(Failure.FETCH_NONCE_SPENT, failure { Approval.parseFetchNonce("$fetchNonce=") })
    }

    // --- the fetch answer --------------------------------------------------------

    @Test
    fun aFetchAnswerRoundTripsAndOpens() {
        val w = wire()
        val parsed = FetchResponse.parse(w.toJson())
        assertContentEquals(w.toJson(), parsed.toJson())
        val opened = parsed.open()
        assertEquals(action, opened.action)
        assertEquals(0, opened.challenge.matchNumber)
        assertEquals(listOf(17, 42, 86), opened.challenge.candidates)
        assertContentEquals(action.digest(), opened.challenge.actionDigest)
    }

    @Test
    fun theAnswerIsReadAsGoUnmarshalsIt() {
        val j = wire().toJson().decodeToString()
        // Case-folded member names, an unknown match_number, and a repeated object merged.
        val folded = j.replace("\"challenge\":", "\"CHALLENGE\":").replace("\"ttl\":", "\"TTL\":")
            .replace("\"action\":{", "\"match_number\":42,\"action\":{")
        assertEquals(action, FetchResponse.parse(folded.encodeToByteArray()).open().action)
        val split = j.replace(",\"action\":{", ",\"action\":{\"kind\":\"deploy\"},\"action\":{")
        assertEquals(action, FetchResponse.parse(split.encodeToByteArray()).open().action)
        val nulled = j.replace("\"summary\":", "\"summary\":\"Deploy web to production\",\"summary\":null,\"x\":")
        assertEquals(action, FetchResponse.parse(nulled.encodeToByteArray()).open().action)
        for (bad in listOf(
            j.replace("\"ttl\":600", "\"ttl\":600.0"),
            j.replace("\"ttl\":600", "\"ttl\":\"600\""),
            j.replace("\"id\":\"", "\"id\":1,\"x\":\""),
            j.replace("\"candidates\":[17,42,86]", "\"candidates\":{}"),
            "[]",
            "{",
            "$j x",
        )) {
            assertEquals(Failure.MALFORMED, failure { FetchResponse.parse(bad.encodeToByteArray()) }, bad)
        }
        assertEquals(Failure.MALFORMED, failure { FetchResponse.parse("null".encodeToByteArray()).open() })
    }

    @Test
    fun goUtf8ReplacesEachInvalidByte() {
        val b = byteArrayOf(
            0x41, 0xE2.toByte(), 0x82.toByte(), 0x41, 0xED.toByte(), 0xA0.toByte(), 0x80.toByte(),
            0xF0.toByte(), 0x9F.toByte(), 0x9A.toByte(), 0x80.toByte(), 0xC0.toByte(), 0x80.toByte(),
        )
        assertEquals("A��A���🚀��", ApprovalJson.goUtf8(b))
    }

    @Test
    fun openRefusesWhatGoRefuses() {
        val good = wire()
        fun with(c: FetchedChallenge.() -> FetchedChallenge) = FetchResponse(good.challenge.c(), good.action)
        fun FetchedChallenge.copy(nonce: String = this.nonce, digest: String = actionDigest, id: String = this.id) =
            FetchedChallenge(id, nonce, audience, issuedAt, expiresAt, candidates, digest, resource, ttl)
        val n = good.challenge.nonce
        assertEquals(
            Failure.MALFORMED,
            failure {
                with { copy(nonce = n.substring(0, 10) + "\n" + n.substring(10)) }.open()
            },
        )
        assertEquals(Failure.MALFORMED, failure { with { copy(nonce = "$n=") }.open() })
        assertEquals(Failure.MALFORMED, failure { with { copy(nonce = Base64Url.encode(ByteArray(32))) }.open() })
        assertEquals(Failure.MALFORMED, failure { with { copy(digest = Base64Url.encode(ByteArray(31))) }.open() })
        assertEquals(Failure.MALFORMED, failure { with { copy(id = "C6E736E7B62631430EDBF305C4113304") }.open() })
        for (cs in listOf(
            null,
            listOf(1L, 2L),
            listOf(1L, 2L, 3L, 4L),
            listOf(1L, 1L, 2L),
            listOf(1L, 2L, 100L),
            listOf(-1L, 2L, 3L),
        )) {
            assertEquals(Failure.MALFORMED, failure { wire(candidates = cs).open() }, "$cs")
        }
        assertEquals(Failure.TTL_TOO_LONG, failure { wire(ttl = 3601).open() })
        assertEquals(Failure.TTL_TOO_LONG, failure { wire(ttl = -1).open() })
        wire(ttl = 0).open()
        wire(ttl = 3600).open()
        // The phone shows what it digests: an altered summary does not recompute.
        val altered = Action(action.kind, action.resource, action.summary + ".", action.params)
        assertEquals(Failure.DIGEST_MISMATCH, failure { wire(a = altered).open() })
        assertEquals(Failure.RESOURCE_MISMATCH, failure { wire(resource = "do:team/other").open() })
        val badParams = FetchResponse(good.challenge, WireAction(action.kind, action.resource, action.summary, "e30="))
        assertEquals(Failure.MALFORMED, failure { badParams.open() })
    }

    // --- signing -----------------------------------------------------------------

    @Test
    fun theApproverSignsOnlyAChosenCandidateOfTheActionItDisplayed() {
        val opened = wire().open()
        val c = opened.challenge
        val a = Approval.signAssertionWith(signer, pub, c, opened.action, 42, "cred")
        key.verifyBody(
            Approval.DOMAIN_CHALLENGE,
            c.withMatchNumber(42).preimage(),
            Base64Url.decode(a.sig),
            WebAuthnPolicy(),
        )
        assertTrue(
            a.toJson().decodeToString().matches(
                Regex("""\{"credential":"cred","sig":"[A-Za-z0-9_-]{86}","match_number":42}"""),
            ),
        )
        assertEquals(
            Failure.MALFORMED,
            failure {
                Approval.signAssertionWith(signer, pub, c, opened.action, 43, "cred")
            },
        )
        assertEquals(Failure.MALFORMED, failure { Approval.signAssertionWith(signer, pub, c, opened.action, 42, "") })
        val other = Action("deploy", "do:team/ops", "Something else", ByteArray(0))
        assertEquals(Failure.DIGEST_MISMATCH, failure { Approval.signAssertionWith(signer, pub, c, other, 42, "cred") })
        assertEquals(Failure.DIGEST_MISMATCH, failure { Approval.passkeyChallenge(c, other, 42) })
        assertEquals(32, Approval.passkeyChallenge(c, opened.action, 17).size)
        val pk = Approval.webAuthnAssertion(
            "cred",
            17,
            Approval.webAuthnEnvelope(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3)),
        )
        assertEquals("""{"ad":"AQ","cd":"Ag","sig":"Aw"}""", Base64Url.decode(pk.sig).decodeToString())
        assertEquals(Failure.MALFORMED, failure { Approval.webAuthnAssertion("cred", 17, ByteArray(0)) })
    }

    @Test
    fun theFetchProofIsBoundToTheAudience() {
        val proof = Approval.signFetchProofWith(signer, pub, audience, handle, fetchNonce)
        val sig = Base64Url.decode(proof)
        key.verifyBody(
            Approval.DOMAIN_FETCH,
            Approval.fetchPreimage(audience, handle, fetchNonce),
            sig,
            WebAuthnPolicy(),
        )
        assertFailsWith<Exception> {
            key.verifyBody(
                Approval.DOMAIN_FETCH,
                Approval.fetchPreimage("https://other.example", handle, fetchNonce),
                sig,
                WebAuthnPolicy(),
            )
        }
        assertEquals(Failure.MALFORMED, failure { Approval.fetchPreimage("", handle, fetchNonce) })
    }

    // --- the client --------------------------------------------------------------

    private class FakeBroker(private val answer: (String, ByteArray?) -> HttpResponse) : HttpTransport {
        val calls = ArrayList<Triple<String, String?, String?>>()

        override fun get(url: String) = error("no GET")

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            calls += Triple(url, body?.decodeToString(), contentType)
            return answer(url, body)
        }

        override fun put(url: String, body: ByteArray, contentType: String?) = error("no PUT")

        override fun sleep(millis: Long) = Unit
    }

    @Test
    fun theClientFetchesWithAProofAndOpensTheAnswer() {
        val broker = FakeBroker { url, _ ->
            when {
                url.endsWith(
                    "/approval/fetch-nonce",
                ) -> HttpResponse(200, "{\"nonce\":\"$fetchNonce\"}".encodeToByteArray())

                else -> HttpResponse(200, wire().toJson())
            }
        }
        val client = ApprovalClient(broker, "https://broker.example/", audience)
        val opened = client.fetchWithEd25519(handle, signer, pub, "cred")
        assertEquals(action, opened.action)
        assertEquals("https://broker.example/approval/fetch-nonce", broker.calls[0].first)
        assertNull(broker.calls[0].second)
        val (url, body, type) = broker.calls[1]
        assertEquals("https://broker.example/approval/fetch", url)
        assertEquals("application/json", type)
        val proof = Regex(""""proof":"([^"]+)"""").find(assertNotNull(body))!!.groupValues[1]
        assertEquals("""{"handle":"$handle","nonce":"$fetchNonce","credential":"cred","proof":"$proof"}""", body)
        key.verifyBody(
            Approval.DOMAIN_FETCH,
            Approval.fetchPreimage(audience, handle, fetchNonce),
            Base64Url.decode(proof),
            WebAuthnPolicy(),
        )
    }

    @Test
    fun theClientSurfacesTheOneRefusalAndOtherStatuses() {
        val refusing = FakeBroker { url, _ ->
            if (url.endsWith("fetch-nonce")) {
                HttpResponse(200, "{\"Nonce\":\"$fetchNonce\"}".encodeToByteArray())
            } else {
                HttpResponse(404, Approval.FETCH_REFUSAL_BODY.encodeToByteArray())
            }
        }
        assertFailsWith<ApprovalFetchRefusedException> {
            ApprovalClient(refusing, "https://broker.example", audience).fetchWithEd25519(handle, signer, pub, "cred")
        }
        val limited = FakeBroker { _, _ -> HttpResponse(429, ByteArray(0)) }
        assertEquals(
            429,
            assertFailsWith<ApprovalHttpException> {
                ApprovalClient(limited, "https://broker.example", audience).fetchNonce()
            }.status,
        )
        val zero =
            FakeBroker { _, _ ->
                HttpResponse(200, "{\"nonce\":\"${Base64Url.encode(ByteArray(32))}\"}".encodeToByteArray())
            }
        assertEquals(Failure.FETCH_NONCE_SPENT, failure { ApprovalClient(zero, "https://b", audience).fetchNonce() })
        val tampered = FakeBroker { url, _ ->
            if (url.endsWith("fetch-nonce")) {
                HttpResponse(200, "{\"nonce\":\"$fetchNonce\"}".encodeToByteArray())
            } else {
                HttpResponse(200, wire(a = Action("deploy", "do:team/ops", "Other", ByteArray(0))).toJson())
            }
        }
        assertEquals(
            Failure.DIGEST_MISMATCH,
            failure {
                ApprovalClient(tampered, "https://b", audience).fetchWithEd25519(handle, signer, pub, "cred")
            },
        )
    }
}
