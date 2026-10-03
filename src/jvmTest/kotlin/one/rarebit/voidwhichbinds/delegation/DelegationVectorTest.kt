package one.rarebit.voidwhichbinds.delegation

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MemberKey
import one.rarebit.voidwhichbinds.WebAuthnPolicy
import one.rarebit.voidwhichbinds.WebAuthnRp
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.delegation.Delegation.DelegationException
import one.rarebit.voidwhichbinds.delegation.Delegation.Failure
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The cross-implementation PARITY suite for the delegation minter (void-which-binds-go
 * ADR-0017, G8): Go's golden vectors, `testvectors/vectors/delegation/` (pinned by
 * `VOID_WHICH_BINDS_GO_REF`), copied verbatim into `src/jvmTest/resources/vectors/delegation/`.
 * Per the vectors' README "Mints" table, every `ed25519` delegation and every `proof`
 * is re-minted byte for byte from its recorded claims and seed (JDK Ed25519 is
 * deterministic); every `webauthn` mint's body is reproduced exactly, its envelope
 * re-assembled into the token, and its assertion verified over [Delegation.challenge];
 * every `hand-built` token is re-signed from its body. [Delegation.parse] round-trips
 * every minted token and refuses the hand-built malformed and mistyped ones. The broker
 * side (`requests`) is server-only and not replayed here.
 */
@Suppress("UNCHECKED_CAST")
class DelegationVectorTest {
    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/delegation") ?: error("vectors/delegation missing")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty()
            .map { it.name.removeSuffix(".json") }.sorted()
            .also { check(it.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS vectors, found ${it.size}" } }
    }

    private fun load(name: String): Map<String, Any> {
        val raw = javaClass.getResourceAsStream("/vectors/delegation/$name.json")!!.readBytes().decodeToString()
        return MiniJson.parseObject(raw).also { assertEquals(name, it["name"], "file stem must equal its name") }
    }

    private class Key(val seed: ByteArray, val pub: ByteArray) {
        val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    }

    private fun keys(v: Map<String, Any>): Map<String, Key> =
        (v["keys"] as Map<String, Map<String, Any>>).filterValues { it["sign_seed"] != null }.mapValues { (label, k) ->
            val seed = Hex.decode(k["sign_seed"] as String)
            val pub = Ed25519Group.publicKeyFromSeed(seed)
            assertEquals(k["id"], KeyRef.ed25519(pub).render(), "key $label: id does not match its seed")
            Key(seed, pub)
        }

    private fun claims(c: Map<String, Any>) = Delegation(
        user = c["usr"] as String,
        org = c["org"] as String,
        issuer = c["iss"] as String,
        principal = c["prn"] as String,
        audience = c["aud"] as String,
        scopes = c["scp"] as List<String>,
        jti = c["jti"] as String,
        nonce = c["non"] as String,
        issuedAt = c["iat"] as Long,
        expiresAt = c["exp"] as Long,
    )

    private fun policy(v: Map<String, Any>) = WebAuthnPolicy(
        (v["webauthn_rps"] as List<Map<String, Any>>).map {
            WebAuthnRp(it["rp_id"] as String, it["origins"] as List<String>)
        },
        // The synced-passkey rule is the broker's, per person kind; the assertion itself is what is checked here.
        allowSynced = true,
    )

    private fun parseOutcome(token: String): String = try {
        Delegation.parse(token)
        "ok"
    } catch (e: DelegationException) {
        e.failure.name.lowercase()
    }

    @Test
    fun everyMintReplays() {
        val counts = HashMap<String, Int>()
        for (name in cases) {
            val v = load(name)
            val ks = keys(v)
            for (m in v["mints"] as List<Map<String, Any>>) {
                val label = "$name/${m["label"]}"
                val kind = m["kind"] as String
                val token = m["token"] as String
                when (kind) {
                    "ed25519" -> replayEd25519(label, m, ks, token)

                    "webauthn" -> replayWebAuthn(label, m, v, token)

                    "proof" -> replayProof(label, m, ks, token)

                    "hand-built" -> replayHandBuilt(label, m, ks, token)

                    "possession", "grant" -> Unit

                    // confusion cases another package mints
                    else -> error("$label: unknown mint kind $kind")
                }
                counts.merge(kind, 1, Int::plus)
            }
        }
        // Every kind the README table names is present, so none is silently skipped.
        for (kind in listOf("ed25519", "webauthn", "proof", "hand-built")) {
            assertTrue((counts[kind] ?: 0) > 0, "no $kind mints replayed: $counts")
        }
    }

    private fun replayEd25519(label: String, m: Map<String, Any>, ks: Map<String, Key>, token: String) {
        val signer = ks.getValue(m["signer"] as String)
        val d = claims(m["claims"] as Map<String, Any>)
        assertEquals(token, Delegation.signWith(signer.signer, signer.pub, d), "$label: re-mint")
        assertEquals(d.copy(scopes = d.scopes.toSortedSet().toList()), Delegation.parse(token), "$label: parse")
    }

    private fun replayWebAuthn(label: String, m: Map<String, Any>, v: Map<String, Any>, token: String) {
        val d = claims(m["claims"] as Map<String, Any>)
        val body = d.body()
        assertEquals(m["body"], body.decodeToString(), "$label: body")
        val (b64Body, b64Env) = token.split('.')
        assertContentEquals(body, Base64Url.decode(b64Body), "$label: token body")
        val envelope = Base64Url.decode(b64Env)
        assertEquals(token, Delegation.assembleWebAuthn(body, envelope), "$label: assemble")
        // The envelope helper reproduces Go's envelope encoding from its three parts.
        val env = MiniJson.parseObject(envelope.decodeToString())
        val rebuilt = Delegation.webAuthnEnvelope(
            Base64Url.decode(env["ad"] as String),
            Base64Url.decode(env["cd"] as String),
            Base64Url.decode(env["sig"] as String),
        )
        assertContentEquals(envelope, rebuilt, "$label: envelope")
        // The assertion is over Challenge(body): it verifies under the issuer.
        MemberKey.parse(d.issuer).verifyBody(Delegation.DOMAIN, body, envelope, policy(v))
        val clientData = MiniJson.parseObject(Base64Url.decode(env["cd"] as String).decodeToString())
        assertEquals(Base64Url.encode(Delegation.challenge(body)), clientData["challenge"], "$label: challenge")
        assertEquals(d.copy(scopes = d.scopes.toSortedSet().toList()), Delegation.parse(token), "$label: parse")
    }

    private fun replayProof(label: String, m: Map<String, Any>, ks: Map<String, Key>, token: String) {
        val signer = ks.getValue(m["signer"] as String)
        val got = Delegation.signProofWith(
            signer.signer,
            signer.pub,
            m["delegation"] as String,
            m["aud"] as String,
            m["iat"] as Long,
            m["ttl"] as Long,
        )
        assertEquals(token, got, "$label: re-mint")
    }

    private fun replayHandBuilt(label: String, m: Map<String, Any>, ks: Map<String, Key>, token: String) {
        val signer = ks.getValue(m["signer"] as String)
        val body = (m["body"] as String).encodeToByteArray()
        assertEquals(
            token,
            Base64Url.encode(body) + "." + Base64Url.encode(signer.signer.sign(body)),
            "$label: re-sign",
        )
        if (MiniJson.parseObject(m["body"] as String)["typ"] == Delegation.TYP_PROOF) {
            assertEquals("wrong_type", parseOutcome(token), "$label: a proof is not a delegation")
            return
        }
        val expect = HAND_BUILT_PARSE[label] ?: error("$label: no expected parse outcome")
        assertEquals(expect, parseOutcome(token), "$label: parse")
    }

    private class Fixture(val d: Delegation, val token: String, val dev: Key, val agent: Key)

    private fun fixture(): Fixture {
        val v = load("ok-ed25519-device")
        val ks = keys(v)
        val m = (v["mints"] as List<Map<String, Any>>).first { it["kind"] == "ed25519" }
        return Fixture(
            claims(m["claims"] as Map<String, Any>),
            m["token"] as String,
            ks.getValue("M.D"),
            ks.getValue("A"),
        )
    }

    private fun refused(f: Failure, block: () -> Unit) =
        assertEquals(f, assertFailsWith<DelegationException> { block() }.failure)

    private fun refusedBody(f: Failure, x: Delegation) = refused(f) { x.body() }

    @Test
    fun scopesAreCanonicalisedAndBodyRefusalsHold() {
        val f = fixture()
        val d = f.d

        // The minter sorts and de-duplicates scp: the same token.
        val shuffled = d.copy(scopes = listOf("app:write", "app:read", "app:write"))
        assertEquals(f.token, Delegation.signWith(f.dev.signer, f.dev.pub, shuffled))

        refusedBody(Failure.INCOMPLETE, d.copy(user = ""))
        refusedBody(Failure.INCOMPLETE, d.copy(nonce = ""))
        refusedBody(Failure.INCOMPLETE, d.copy(issuedAt = 0))
        refusedBody(Failure.INCOMPLETE, d.copy(expiresAt = d.issuedAt))
        refusedBody(Failure.INCOMPLETE, d.copy(issuedAt = -1))
        refusedBody(Failure.TTL_TOO_LONG, d.copy(expiresAt = d.issuedAt + Delegation.MAX_TTL_SECONDS + 1))
        d.copy(expiresAt = d.issuedAt + Delegation.MAX_TTL_SECONDS).body()
        refusedBody(Failure.MALFORMED_SCOPE, d.copy(scopes = emptyList()))
        refusedBody(Failure.MALFORMED_SCOPE, d.copy(scopes = listOf("APP:read")))
        refusedBody(Failure.MALFORMED_SCOPE, d.copy(scopes = (0..32).map { "app:s$it" }))
        refusedBody(Failure.PRINCIPAL_IS_ISSUER, d.copy(principal = d.issuer))
        refusedBody(Failure.PRINCIPAL_IS_ISSUER, d.copy(principal = d.user))
        refusedBody(Failure.PRINCIPAL_IS_ISSUER, d.copy(principal = d.org))
        refusedBody(Failure.ISSUER_MISMATCH, d.copy(issuer = d.user))
        refusedBody(Failure.ISSUER_MISMATCH, d.copy(issuer = d.org))
        refusedBody(Failure.MALFORMED, d.copy(user = d.user.uppercase()))
        refusedBody(Failure.MALFORMED, d.copy(user = "mp:ABCDEF00112233445566778899aabbcc"))
        refusedBody(Failure.MALFORMED, d.copy(issuer = "webauthn:es256:00"))
        refusedBody(Failure.MALFORMED, d.copy(jti = Base64Url.encode(ByteArray(15))))
        refusedBody(Failure.MALFORMED, d.copy(jti = d.jti.dropLast(1) + "R")) // non-zero trailing bits
        refusedBody(Failure.MALFORMED, d.copy(nonce = d.jti))

        // Fresh random claims have the lengths the grammar requires.
        assertEquals(22, Delegation.newJti().length)
        assertEquals(43, Delegation.newNonce().length)
        d.copy(jti = Delegation.newJti(), nonce = Delegation.newNonce()).body()
    }

    @Test
    fun signerAndProofRefusalsHold() {
        val f = fixture()
        val d = f.d
        val token = f.token
        val dev = f.dev
        val agent = f.agent

        // SignWith: iss must be the signing key; a webauthn issuer mints through a ceremony.
        refused(Failure.ISSUER_MISMATCH) { Delegation.signWith(agent.signer, agent.pub, d) }
        val passkeyIss = (load("ok-webauthn-issuer")["keys"] as Map<String, Map<String, Any>>)
            .getValue("M.W")["id"] as String
        refused(Failure.ISSUER_MISMATCH) { Delegation.signWith(dev.signer, dev.pub, d.copy(issuer = passkeyIss)) }

        // AssembleWebAuthn: a passkey body and a non-empty envelope only.
        refused(Failure.ISSUER_MISMATCH) { Delegation.assembleWebAuthn(d.body(), byteArrayOf(1)) }
        refused(Failure.INCOMPLETE) { Delegation.assembleWebAuthn(d.copy(issuer = passkeyIss).body(), ByteArray(0)) }

        // SignProofWith: the agent key only, an audience, a ttl within PossessionTTL.
        val now = d.issuedAt + 60
        refused(Failure.ISSUER_MISMATCH) { Delegation.signProofWith(dev.signer, dev.pub, token, d.audience, now) }
        refused(Failure.INCOMPLETE) { Delegation.signProofWith(agent.signer, agent.pub, token, "", now) }
        refused(Failure.TTL_TOO_LONG) {
            Delegation.signProofWith(
                agent.signer,
                agent.pub,
                token,
                d.audience,
                now,
                Delegation.POSSESSION_TTL_SECONDS + 1,
            )
        }
        refused(Failure.MALFORMED) { Delegation.signProofWith(agent.signer, agent.pub, "no-dot", d.audience, now) }
        assertEquals(
            Delegation.signProofWith(
                agent.signer,
                agent.pub,
                token,
                d.audience,
                now,
                Delegation.POSSESSION_TTL_SECONDS,
            ),
            Delegation.signProofWith(agent.signer, agent.pub, token, d.audience, now),
            "a zero ttl is PossessionTTL",
        )
        val proof = Delegation.signProofWith(agent.signer, agent.pub, token, d.audience, now)
        assertEquals("wrong_type", parseOutcome(proof))
        assertEquals(
            Delegation.bodyHash(token),
            MiniJson.parseObject(Base64Url.decode(proof.substringBefore('.')).decodeToString())["dlg"],
        )
    }

    @Test
    fun goHtmlEscapingIsReproduced() {
        val v = load("aud-with-ampersand")
        val m = (v["mints"] as List<Map<String, Any>>).first { it["kind"] == "ed25519" }
        val d = claims(m["claims"] as Map<String, Any>)
        val body = d.body().decodeToString()
        assertTrue("\"aud\":\"https://b.example/?a=1\\u0026b=2\"" in body, body)
        assertEquals(
            "{\"x\":\"a\\u003cb\\u003e\\u0026c\"}",
            DelegationJson.obj("x" to "a<b>&c").decodeToString(),
        )
    }

    private companion object {
        const val MIN_VECTORS = 52

        /** [Delegation.parse]'s outcome for each hand-built delegation (not proof) body. */
        val HAND_BUILT_PARSE = mapOf(
            "aud-with-ampersand/literal" to "malformed",
            "bad-signature/d" to "ok",
            "gen1-typ/d" to "wrong_type",
            "issuer-is-genesis/d" to "ok",
            "managed-issuer-is-org-key/d" to "ok",
            "nonce-missing/d" to "malformed",
            "scope-grammar/uppercase" to "malformed",
            "scope-grammar/wildcard" to "malformed",
            "scope-grammar/empty-scope" to "malformed",
            "scope-grammar/empty-list" to "malformed",
            "scope-grammar/unsorted" to "malformed",
            "scope-grammar/duplicate" to "malformed",
            "scope-grammar/thirty-three" to "malformed",
            "ttl-over-max-at-verify/d" to "malformed",
        )
    }
}
