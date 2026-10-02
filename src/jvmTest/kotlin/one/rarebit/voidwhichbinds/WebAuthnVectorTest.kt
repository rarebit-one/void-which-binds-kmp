package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * void-which-binds-go's ADR-0018 WebAuthn member-key vectors
 * (`testvectors/vectors/webauthn/`, copied verbatim and pinned by
 * `VOID_WHICH_BINDS_GO_REF`), replayed verify-only exactly as Go's
 * `TestWebAuthnVectorVerdicts` replays them: parse the key, verify the segment, and
 * compare ADR-0018's refusal word. Every case has exactly one defect, so the verdict
 * does not depend on check order (`WebAuthnVerifyTest` pins the order).
 */
class WebAuthnVectorTest {

    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/webauthn") ?: error("vectors/webauthn missing from test resources")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }
            .orEmpty()
            .map { it.name.removeSuffix(".json") }
            .sorted()
            .also {
                check(it.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS webauthn vectors, found ${it.size}: $it" }
            }
    }

    private val knownFields = setOf(
        "name", "description", "key", "domain", "body", "challenge", "segment", "policy", "expect", "signature_valid",
    )

    @Suppress("UNCHECKED_CAST")
    private fun policyOf(o: Map<String, Any>?): WebAuthnPolicy {
        if (o == null) return WebAuthnPolicy()
        val rps = (o["rps"] as List<Map<String, Any>>).map { rp ->
            WebAuthnRp(rp["rp_id"] as String, (rp["origins"] as List<String>))
        }
        return WebAuthnPolicy(rps, o["allow_synced"] as Boolean)
    }

    @Suppress("UNCHECKED_CAST", "CyclomaticComplexMethod")
    private fun replay(name: String): String {
        val raw = javaClass.getResourceAsStream("/vectors/webauthn/$name.json")?.readBytes()?.decodeToString()
            ?: error("vector $name.json missing")
        val v = MiniJson.parseObject(raw)
        assertEquals(name, v["name"], "vector name must equal its file stem")
        val unknown = v.keys - knownFields
        assertTrue(unknown.isEmpty(), "$name: unknown fields $unknown")
        val expect = v["expect"] as String

        val key = try {
            MemberKey.parse(v["key"] as String)
        } catch (e: MemberKeyException) {
            assertTrue(v["segment"] == null, "$name: ParseMemberKey refused a key with a segment: ${e.message}")
            assertEquals(MemberKeyFailure.MALFORMED_PUBLIC_KEY, e.failure, name)
            return MemberKey.reason(e)
        }
        val segment = v["segment"] as? String ?: fail("$name: key-string case parsed, expect $expect")
        val seg = Base64Url.decode(segment)
        val pol = policyOf(v["policy"] as Map<String, Any>?)
        val domain = v["domain"] as String?
        val err = runCatching {
            if (domain != null) {
                val body = Hex.decode(v["body"] as String)
                if (key.kind == MemberKey.Kind.WEBAUTHN) {
                    assertEquals(
                        v["challenge"],
                        Hex.encode(WebAuthn.challenge(domain, body)),
                        "$name: WebAuthnChallenge known answer",
                    )
                }
                key.verifyBody(domain, body, seg, pol)
            } else {
                key.verifyWebAuthnChallenge(Hex.decode(v["challenge"] as String), seg, pol)
            }
        }.exceptionOrNull()
        if (err != null && err !is MemberKeyException) throw err
        (v["signature_valid"] as Boolean?)?.let { want ->
            assertEquals(want, rawEs256Valid(key.toString(), seg), "$name: raw ES256 signature validity")
        }
        return MemberKey.reason(err)
    }

    @Test
    fun everyVectorReachesItsVerdict() {
        val seen = mutableSetOf<String>()
        val failures = mutableListOf<String>()
        for (name in cases) {
            val raw = javaClass.getResourceAsStream("/vectors/webauthn/$name.json")!!.readBytes().decodeToString()
            val expect = MiniJson.parseObject(raw)["expect"] as String
            seen += expect
            val got = replay(name)
            if (got != expect) failures += "$name: verdict $got, expect $expect"
        }
        assertTrue(failures.isEmpty(), failures.joinToString("\n"))
        val words = listOf(
            "ok", "malformed", "wrong_ceremony", "challenge_mismatch", "origin_not_allowed",
            "rp_id_mismatch", "user_not_present", "user_not_verified", "synced_not_allowed", "bad_signature",
        )
        assertEquals(words.toSet(), seen, "every ADR-0018 refusal word must have a vector")
    }

    /** The envelope's signature over authData ‖ SHA-256(clientDataJSON), with nothing else. */
    private fun rawEs256Valid(key: String, seg: ByteArray): Boolean {
        val env = MiniJson.parseObject(seg.decodeToString())
        val ad = Base64Url.decode(env["ad"] as String)
        val cd = Base64Url.decode(env["cd"] as String)
        val sig = Base64Url.decode(env["sig"] as String)
        val point = Hex.decode(key.removePrefix("webauthn:es256:"))
        val provider = CryptographyProvider.Default
        val pub = provider.get(
            ECDSA,
        ).publicKeyDecoder(EC.Curve.P256).decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW, point)
        val msg = ad + provider.get(SHA256).hasher().hashBlocking(cd)
        return pub.signatureVerifier(SHA256, ECDSA.SignatureFormat.DER).tryVerifySignatureBlocking(msg, sig)
    }

    private companion object {
        /** void-which-binds-go e73d507 ships 41; the floor guards a broken enumeration. */
        const val MIN_VECTORS = 41
    }
}
