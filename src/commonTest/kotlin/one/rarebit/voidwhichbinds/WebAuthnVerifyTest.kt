package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.TestPasskey.Companion.DELEGATION
import one.rarebit.voidwhichbinds.TestPasskey.Companion.FLAG_AT
import one.rarebit.voidwhichbinds.TestPasskey.Companion.FLAG_BE
import one.rarebit.voidwhichbinds.TestPasskey.Companion.FLAG_BS
import one.rarebit.voidwhichbinds.TestPasskey.Companion.FLAG_ED
import one.rarebit.voidwhichbinds.TestPasskey.Companion.FLAG_UP
import one.rarebit.voidwhichbinds.TestPasskey.Companion.FLAG_UV
import one.rarebit.voidwhichbinds.TestPasskey.Companion.ORIGIN
import one.rarebit.voidwhichbinds.TestPasskey.Companion.b64
import one.rarebit.voidwhichbinds.TestPasskey.Companion.clientData
import one.rarebit.voidwhichbinds.TestPasskey.Companion.envelope
import one.rarebit.voidwhichbinds.TestPasskey.Companion.policy
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * `MemberKey.verifyBody` (void-which-binds-go `VerifyBody`, ADR-0018 §7.2). The Go
 * vectors give every case exactly one defect; these cases give an assertion TWO
 * defects and pin which check reports first, so the order is Go's: envelope, then
 * clientDataJSON, then the authenticatorData layout, then type, challenge, origin
 * (crossOrigin, topOrigin), rpIdHash, UP, UV, BS-without-BE, synced policy, and the
 * signature last. Also ports Go's `memberkey_test.go` strictness cases.
 */
class WebAuthnVerifyTest {

    private val body = "body".encodeToByteArray()
    private val challenge = WebAuthn.challenge(DELEGATION, body)
    private val ch = b64(challenge)

    /** The three required clientDataJSON members, correct for [body]. */
    private val base = """"type":"webauthn.get","challenge":"$ch","origin":"$ORIGIN""""

    /** clientDataJSON from raw member text. */
    private fun cdj(members: String) = "{$members}".encodeToByteArray()

    private fun verdict(
        pk: TestPasskey,
        seg: ByteArray,
        pol: WebAuthnPolicy = policy,
        domain: String = DELEGATION,
        key: MemberKey = pk.key,
    ): String = MemberKey.reason(runCatching { key.verifyBody(domain, body, seg, pol) }.exceptionOrNull())

    /** A correctly signed envelope over [cd] (with [pk]'s current authData unless [ad] is given). */
    private fun signed(pk: TestPasskey, cd: ByteArray, ad: ByteArray = pk.authData()) = pk.complete(ad, cd)

    private fun cd(
        type: String = "webauthn.get",
        c: ByteArray = challenge,
        origin: String = ORIGIN,
        tail: String = "",
    ) = clientData(type, c, origin, tail)

    @Test
    fun acceptsAValidAssertion() {
        val pk = TestPasskey()
        assertEquals("ok", verdict(pk, pk.assert(DELEGATION, body)))
        pk.flags = FLAG_UP or FLAG_UV or FLAG_BE or FLAG_BS
        assertEquals("ok", verdict(pk, pk.assert(DELEGATION, body), policy.copy(allowSynced = true)))
        pk.flags = FLAG_UP or FLAG_UV or FLAG_ED
        pk.extensions = byteArrayOf(0xa0.toByte()) // an empty CBOR map
        assertEquals("ok", verdict(pk, pk.assert(DELEGATION, body)))
    }

    private class OrderCase(val name: String, val want: String, val mint: () -> ByteArray)

    @Test
    fun checkOrder() {
        val pk = TestPasskey()
        for (c in orderCases(pk)) {
            pk.rpId = TestPasskey.RP_ID
            pk.flags = FLAG_UP or FLAG_UV
            val seg = c.mint()
            assertEquals(c.want, verdict(pk, seg), c.name)
        }
    }

    /** Each case bends [pk] (reset before each) and mints an envelope with two defects. */
    private fun orderCases(pk: TestPasskey): List<OrderCase> {
        val other = WebAuthn.challenge(DELEGATION, "other".encodeToByteArray())
        val evil = "https://evil.example"
        fun otherKeySig() = envelope(pk.authData(), cd(), TestPasskey().sign(pk.authData(), cd()))
        return listOf(
            // Structure before semantics.
            OrderCase("AT set + wrong type", "malformed") {
                pk.flags = FLAG_UP or FLAG_UV or FLAG_AT
                signed(pk, cd(type = "webauthn.create"))
            },
            OrderCase("duplicate clientData key + wrong type", "malformed") {
                signed(pk, cdj(""""type":"webauthn.create","challenge":"$ch","origin":"$ORIGIN","origin":"$ORIGIN""""))
            },
            OrderCase("short authData + wrong type", "malformed") {
                signed(pk, cd(type = "x"), pk.authData().copyOf(AUTH_DATA_SHORT))
            },
            // §7.2 order.
            OrderCase("wrong type + wrong challenge", "wrong_ceremony") {
                signed(pk, cd(type = "webauthn.create", c = other))
            },
            OrderCase("wrong challenge + bad origin", "challenge_mismatch") {
                signed(pk, cd(c = other, origin = evil))
            },
            OrderCase("bad origin + rpId mismatch", "origin_not_allowed") {
                pk.rpId = "evil.example"
                signed(pk, cd(origin = evil))
            },
            OrderCase("crossOrigin + rpId mismatch", "origin_not_allowed") {
                pk.rpId = "evil.example"
                signed(pk, cdj("""$base,"crossOrigin":true"""))
            },
            OrderCase("topOrigin + rpId mismatch", "origin_not_allowed") {
                pk.rpId = "evil.example"
                signed(pk, cd(tail = ""","topOrigin":"https://embedder.example""""))
            },
            OrderCase("rpId mismatch + UP clear", "rp_id_mismatch") {
                pk.rpId = "evil.example"
                pk.flags = FLAG_UV
                signed(pk, cd())
            },
            OrderCase("UP clear + UV clear", "user_not_present") {
                pk.flags = 0
                signed(pk, cd())
            },
            OrderCase("UV clear + synced", "user_not_verified") {
                pk.flags = FLAG_UP or FLAG_BE
                signed(pk, cd())
            },
            OrderCase("BS without BE + bad signature", "malformed") {
                pk.flags = FLAG_UP or FLAG_UV or FLAG_BS
                otherKeySig()
            },
            OrderCase("synced + bad signature", "synced_not_allowed") {
                pk.flags = FLAG_UP or FLAG_UV or FLAG_BE
                otherKeySig()
            },
            OrderCase("another key's signature", "bad_signature") { otherKeySig() },
        )
    }

    @Test
    fun envelopeRules() {
        val pk = TestPasskey()
        val ad = b64(pk.authData())
        val cdB = cd()
        val c = b64(cdB)
        val sigBytes = pk.sign(pk.authData(), cdB)
        val sig = b64(sigBytes)
        val stdSig = sig.replace('-', '+').replace('_', '/')
        val deep = "[".repeat(StrictJsonDepth.OVER) + "]".repeat(StrictJsonDepth.OVER)
        val big = 20 shl 10
        fun env(json: String) = json.encodeToByteArray()
        val cases = listOf(
            "not JSON (a bare signature)" to (ByteArray(64) { 7 } to "bad_signature"),
            "JSON array" to (env("""["$ad"]""") to "bad_signature"),
            "invalid JSON object" to (env("""{"ad":"$ad",}""") to "bad_signature"),
            "trailing data" to (env("""{"ad":"$ad","cd":"$c","sig":"$sig"} x""") to "bad_signature"),
            "missing sig" to (env("""{"ad":"$ad","cd":"$c"}""") to "malformed"),
            "extra member" to (env("""{"ad":"$ad","cd":"$c","sig":"$sig","x":"y"}""") to "malformed"),
            "renamed member" to (env("""{"ad":"$ad","cd":"$c","Sig":"$sig"}""") to "malformed"),
            "duplicate sig" to (env("""{"ad":"$ad","cd":"$c","sig":"$sig","sig":"AAAA"}""") to "malformed"),
            "non-string ad" to (env("""{"ad":1,"cd":"$c","sig":"$sig"}""") to "malformed"),
            "empty sig" to (env("""{"ad":"$ad","cd":"$c","sig":""}""") to "malformed"),
            "padded ad" to (env("""{"ad":"$ad=","cd":"$c","sig":"$sig"}""") to "malformed"),
            "standard-alphabet sig" to
                (env("""{"ad":"$ad","cd":"$c","sig":"$stdSig"}""") to if (stdSig != sig) "malformed" else "ok"),
            "escaped newline in ad" to (env("""{"ad":"$ad\n","cd":"$c","sig":"$sig"}""") to "malformed"),
            "nested too deeply" to (env("""{"ad":"$ad","cd":"$c","sig":"$sig","x":$deep}""") to "malformed"),
            "whitespace around it" to (env(""" {"ad" : "$ad", "cd":"$c","sig":"$sig"} """) to "ok"),
            "oversized" to (env("""{"ad":"${"A".repeat(big)}"}""") to "malformed"),
            "oversized non-JSON" to (ByteArray(big) { 'x'.code.toByte() } to "malformed"),
        )
        for ((name, pair) in cases) {
            assertEquals(pair.second, verdict(pk, pair.first), name)
        }
        // Non-zero unused trailing bits: 37 bytes encode to 50 symbols whose last one
        // carries 2 unused bits; Go's Strict() decoder refuses a non-canonical one.
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val bumped = ad.dropLast(1) + alphabet[alphabet.indexOf(ad.last()) + 1]
        assertEquals("malformed", verdict(pk, env("""{"ad":"$bumped","cd":"$c","sig":"$sig"}""")), "non-canonical bits")
    }

    /** Go `TestClientDataStrictness` and more: each one correctly signed, so only the parse can refuse it. */
    @Test
    fun clientDataStrictness() {
        val pk = TestPasskey()
        val cases = listOf(
            Triple(
                "spaced members",
                """{ "type" : "webauthn.get" , "challenge" : "$ch" , "origin" : "$ORIGIN" }""",
                "ok",
            ),
            Triple("extra members", """{$base,"other_keys_can_be_added_here":"x","extraData":{"a":[1,2]}}""", "ok"),
            Triple("escaped member name", """{"type":"webauthn.get","challenge":"$ch","origin":"$ORIGIN"}""", "ok"),
            Triple(
                "case-variant name",
                """{"Type":"webauthn.get","challenge":"$ch","origin":"$ORIGIN"}""",
                "malformed",
            ),
            Triple("nested duplicate", """{$base,"x":{"a":1,"a":2}}""", "malformed"),
            Triple("escaped duplicate", """{$base,"type":"webauthn.create"}""", "malformed"),
            Triple("duplicate type", """{$base,"type":"webauthn.create"}""", "malformed"),
            Triple("non-string type", """{"type":1,"challenge":"$ch","origin":"$ORIGIN"}""", "malformed"),
            Triple("missing origin", """{"type":"webauthn.get","challenge":"$ch"}""", "malformed"),
            Triple("crossOrigin not boolean", """{$base,"crossOrigin":"false"}""", "malformed"),
            Triple("crossOrigin null", """{$base,"crossOrigin":null}""", "malformed"),
            Triple("topOrigin null is still present", """{$base,"topOrigin":null}""", "origin_not_allowed"),
            Triple("trailing data", """{$base} {}""", "malformed"),
            Triple("array", """["webauthn.get"]""", "malformed"),
            Triple("overflowing number", """{$base,"n":1e400}""", "malformed"),
            Triple("leading-zero number", """{$base,"n":01}""", "malformed"),
            Triple("raw control character", "{$base,\"x\":\"a\u0001b\"}", "malformed"),
            Triple(
                "padded challenge",
                """{"type":"webauthn.get","challenge":"$ch=","origin":"$ORIGIN"}""",
                "challenge_mismatch",
            ),
            Triple(
                "surrogate-escaped origin",
                """{"type":"webauthn.get","challenge":"$ch","origin":"\ud800"}""",
                "origin_not_allowed",
            ),
        )
        for ((name, json, want) in cases) {
            assertEquals(want, verdict(pk, signed(pk, json.encodeToByteArray())), name)
        }
        // Invalid UTF-8 (a lone 0xff inside a string) is malformed even when signed.
        val bad = cdj("""$base,"x":"?"""")
        bad[bad.size - 3] = 0xff.toByte()
        assertEquals("malformed", verdict(pk, signed(pk, bad)), "invalid utf-8")
        // One leading BOM is stripped (the signature covers the bytes as sent).
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())
        assertEquals("ok", verdict(pk, signed(pk, bom + cd())), "BOM")
        assertEquals("malformed", verdict(pk, signed(pk, bom + bom + cd())), "two BOMs")
    }

    @Test
    fun emptyPolicyRefusesEveryOrigin() {
        val pk = TestPasskey()
        assertEquals("origin_not_allowed", verdict(pk, pk.assert(DELEGATION, body), WebAuthnPolicy()))
    }

    @Test
    fun invalidDomainIsMalformed() {
        val pk = TestPasskey()
        for (d in listOf("", "a\u0000b")) {
            val e = runCatching { pk.key.verifyBody(d, body, pk.assert(d, body), policy) }.exceptionOrNull()
            assertEquals(MemberKeyFailure.INVALID_DOMAIN, (e as? MemberKeyException)?.failure, "domain \"$d\"")
            assertEquals("malformed", MemberKey.reason(e))
        }
    }

    @Test
    fun otherDomainIsChallengeMismatch() {
        val pk = TestPasskey()
        val seg = pk.assert(DELEGATION, body)
        assertEquals("challenge_mismatch", verdict(pk, seg, domain = "void-which-binds/approval/challenge/v1"))
    }

    @Test
    fun schemeComesFromTheKeyKind() {
        val pk = TestPasskey()
        val seed = ByteArray(32) { it.toByte() }
        val edKey = MemberKey.parse(KeyRef.ed25519(Ed25519Group.publicKeyFromSeed(seed)).render())
        val edSig = Ed25519Engine.sign(seed, body)
        fun edVerdict(sig: ByteArray, domain: String, pol: WebAuthnPolicy) =
            MemberKey.reason(runCatching { edKey.verifyBody(domain, body, sig, pol) }.exceptionOrNull())
        // An ed25519 key ignores domain and policy.
        assertEquals("ok", edVerdict(edSig, "", WebAuthnPolicy()))
        // An ed25519 key handed a valid webauthn envelope, and a webauthn key handed a
        // bare Ed25519 signature, are both bad_signature.
        assertEquals("bad_signature", verdict(pk, pk.assert(DELEGATION, body), key = edKey))
        assertEquals("bad_signature", verdict(pk, edSig))
        val flipped = edSig.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals("bad_signature", edVerdict(flipped, DELEGATION, policy))
    }

    private object StrictJsonDepth {
        /** One more nesting level than void-which-binds-go's maxJSONDepth (16) allows. */
        const val OVER = 17
    }

    private companion object {
        /** authenticatorData with the sign count truncated (36 of 37 bytes). */
        const val AUTH_DATA_SHORT = 36
    }
}
