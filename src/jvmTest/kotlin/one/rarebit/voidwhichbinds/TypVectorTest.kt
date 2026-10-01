package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.auth.PossessionProof
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The ADR-0009 token-type (`typ`) vectors: void-which-binds-go's `testvectors/vectors/typ/`,
 * copied verbatim into `src/jvmTest/resources/vectors/typ/` (see the README beside
 * them) and replayed through this library's verifiers at their phase-1 ("accept")
 * verdicts.
 *
 * This library ports the op, op-user and possession verifiers, and those checks
 * replay in full. It has no grant verifier and no pinned-key/clock `VerifyCert`
 * (a device mints certs, it doesn't authenticate them), so for `cert`/`cert_user`
 * checks it asserts the part it does own: [Cert.parse] refuses every token Go
 * calls `wrong_type`. `grant` checks are Go-only.
 */
class TypVectorTest {

    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/typ") ?: error("vectors/typ missing from test resources")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty()
            .map { it.name.removeSuffix(".json") }.sorted()
            .also { check(it.size >= 8) { "expected >= 8 typ vectors, found $it" } }
    }

    @Suppress("UNCHECKED_CAST")
    private fun load(name: String): Map<String, Any> {
        val raw = javaClass.getResourceAsStream("/vectors/typ/$name.json")?.readBytes()?.decodeToString()
            ?: error("vector $name.json missing")
        return MiniJson.parseObject(raw).also { assertEquals(name, it["name"]) }
    }

    @Suppress("UNCHECKED_CAST")
    private fun keyBytes(f: Map<String, Any>, label: String): ByteArray {
        val key = (f["keys"] as Map<String, Any>)[label] as Map<String, Any>
        return KeyRef.parse(key["id"] as String).bytes
    }

    private fun verdict(f: Map<String, Any>, c: Map<String, Any>, tokens: Map<String, String>): String? {
        val tok = tokens[c["token"] as String] ?: fail("unknown token ${c["token"]}")
        val now = f["now"] as Long
        return when (c["verifier"] as String) {
            "op" -> {
                try {
                    MembershipOp.verify(tok)
                    "ok"
                } catch (e: MembershipOp.OpException) {
                    opFailure(e.failure)
                }
            }

            "op_user" -> {
                try {
                    MembershipOp.user(tok)
                    "ok"
                } catch (e: MembershipOp.OpException) {
                    opFailure(e.failure)
                }
            }

            "possession" -> possessionVerdict(f, c, tok, tokens, now)

            else -> null // cert / cert_user / grant: see replayCertTypeRefusals
        }
    }

    private fun possessionVerdict(
        f: Map<String, Any>,
        c: Map<String, Any>,
        tok: String,
        tokens: Map<String, String>,
        now: Long,
    ): String = try {
        val cert = tokens[c["cert"] as String]!!
        PossessionProof.verify(tok, keyBytes(f, c["key"] as String), cert, now, Ed25519Engine.verifier())
        "ok"
    } catch (e: PossessionProof.Refused) {
        when (e.reason) {
            PossessionProof.Reason.WRONG_TYPE -> "wrong_type"
            PossessionProof.Reason.BAD_SIGNATURE -> "bad_signature"
            PossessionProof.Reason.WRONG_CERT -> "cert_mismatch"
            PossessionProof.Reason.EXPIRED -> "expired"
            PossessionProof.Reason.NOT_YET_VALID -> "not_yet_valid"
            PossessionProof.Reason.MALFORMED -> "malformed"
        }
    }

    private fun opFailure(f: MembershipOp.Failure) = when (f) {
        MembershipOp.Failure.WRONG_TYPE -> "wrong_type"
        MembershipOp.Failure.BAD_SIGNATURE -> "bad_signature"
        else -> "malformed"
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun replayPhaseOneVerdicts() {
        var replayed = 0
        for (name in cases) {
            val f = load(name)
            val tokens = f["tokens"] as Map<String, String>
            for (c in f["checks"] as List<Map<String, Any>>) {
                val want = (c["expect"] as Map<String, Any>)["accept"] as String
                val got = verdict(f, c, tokens) ?: continue
                assertEquals(want, got, "$name: ${c["verifier"]}(${c["token"]})")
                replayed++
            }
        }
        assertTrue(replayed >= 25, "replayed only $replayed typ checks")
    }

    /** Every token Go's cert verifier calls `wrong_type`, [Cert.parse] refuses as such. */
    @Suppress("UNCHECKED_CAST")
    @Test
    fun replayCertTypeRefusals() {
        var n = 0
        for (name in cases) {
            val f = load(name)
            val tokens = f["tokens"] as Map<String, String>
            val wrongTypeAtCert = (f["checks"] as List<Map<String, Any>>).filter {
                val accept = (it["expect"] as Map<String, Any>)["accept"]
                it["verifier"] in setOf("cert", "cert_user") && accept == "wrong_type"
            }
            for (c in wrongTypeAtCert) {
                val e = runCatching { Cert.parse(tokens[c["token"] as String]!!) }.exceptionOrNull()
                assertTrue(
                    e is TokenType.TypeException && e.failure == TokenType.Failure.WRONG_TYPE,
                    "$name: Cert.parse(${c["token"]}) = $e, want WRONG_TYPE",
                )
                n++
            }
        }
        assertTrue(n >= 8, "only $n cert wrong_type checks")
    }

    /**
     * The phase-2 emit paths ([MembershipOp.signTyped], [PossessionProof.mintTyped],
     * a [Cert] with [Cert.typ]) mint exactly Go's typed vector tokens: `typ` second,
     * after `v`, byte for byte.
     */
    @Suppress("UNCHECKED_CAST")
    @Test
    fun typedMintersMatchGo() {
        fun signer(f: Map<String, Any>, label: String): Ed25519Signer {
            val seed = Hex.decode(((f["keys"] as Map<String, Any>)[label] as Map<String, Any>)["sign_seed"] as String)
            return Ed25519Signer { Ed25519Engine.sign(seed, it) }
        }
        fun body(tok: String) = MiniJson.parseObject(Base64Url.decode(tok.substringBefore('.')).decodeToString())

        load("typed-cert").let { f ->
            val tok = (f["tokens"] as Map<String, String>)["token"]!!
            val parsed = Cert.parse(tok)
            assertEquals(TokenType.CERT, parsed.cert.typ)
            assertEquals(tok, parsed.cert.encode(signer(f, "user")))
            // A new Cert (default typ) mints the typed cert.
            val c = parsed.cert
            val fresh = Cert(c.version, c.user, c.device, c.deviceEnc, c.issuedAt, c.expiresAt)
            assertEquals(tok, fresh.encode(signer(f, "user")))
            assertTrue(parsed.verify(Ed25519Engine.verifier()))
        }
        load("typed-possession").let { f ->
            val toks = f["tokens"] as Map<String, String>
            val b = body(toks["token"]!!)
            val iat = b["iat"] as Long
            val ttl = (b["exp"] as Long) - iat
            val got = PossessionProof.mintTyped(TokenType.POSSESSION, toks["cert"]!!, signer(f, "device"), iat, ttl)
            assertEquals(toks["token"], got)
        }
        load("typed-op").let { f ->
            val tok = (f["tokens"] as Map<String, String>)["token"]!!
            val op = MembershipOp.verify(tok)
            assertEquals(TokenType.OP, op.typ)
            val got = MembershipOp.signTyped(
                TokenType.OP, signer(f, "user"), keyBytes(f, "user"), op.user, op.kind, op.device, op.deviceEnc,
                op.prev, op.issuedAt, op.expiresAt - op.issuedAt,
            )
            assertEquals(tok, got)
            // The cosig core of a typed op is exactly its signed body (no cosig).
            val signedBody = Base64Url.decode(tok.substringBefore('.')).decodeToString()
            assertEquals(signedBody, MembershipOp.coreBytes(op).decodeToString())
        }
        // Phase 2: the public minters ARE the typed paths.
        load("typed-op").let { f ->
            val tok = (f["tokens"] as Map<String, String>)["token"]!!
            val op = MembershipOp.verify(tok)
            val pub = MembershipOp.sign(
                signer(f, "user"), keyBytes(f, "user"), op.user, op.kind, op.device, op.deviceEnc,
                op.prev, op.issuedAt, op.expiresAt - op.issuedAt,
            )
            assertEquals(tok, pub, "MembershipOp.sign must emit the typed op")
        }
        load("typed-possession").let { f ->
            val toks = f["tokens"] as Map<String, String>
            val b = body(toks["token"]!!)
            val iat = b["iat"] as Long
            val pub = PossessionProof.mint(toks["cert"]!!, signer(f, "device"), iat, (b["exp"] as Long) - iat)
            assertEquals(toks["token"], pub, "PossessionProof.mint must emit the typed proof")
        }
    }
}
