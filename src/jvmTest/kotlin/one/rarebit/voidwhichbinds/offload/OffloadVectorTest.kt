package one.rarebit.voidwhichbinds.offload

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The cross-implementation PARITY suite for the cruciform-offload wire (ADR-0098):
 * the golden vectors heyarr-core's `TestOffloadWireVectors` emits, replayed here
 * byte-for-byte — exactly as [one.rarebit.voidwhichbinds.MembershipVectorTest] replays
 * the membership vectors. A vector that passes in Go and fails here is a divergence
 * in the phone-half port. The offload wire is heyarr-core-local, so the Go side is
 * authoritative and this file must not "improve" an encoding.
 */
class OffloadVectorTest {

    @Suppress("UNCHECKED_CAST")
    private val vectors: Map<String, Any> = MiniJson.parseObject(
        javaClass.getResourceAsStream("/vectors/offload/offload_vectors.json")
            ?.readBytes()?.decodeToString()
            ?: error("offload_vectors.json missing from test resources"),
    )

    @Suppress("UNCHECKED_CAST")
    private fun section(name: String) = vectors[name] as Map<String, Any>

    private fun Map<String, Any>.str(k: String) = this[k] as String
    private fun Map<String, Any>.bytes(k: String) = Hex.decode(this[k] as String)

    @Test
    fun inviteRoundTrips() {
        val v = section("invite")
        val salt = Hex.decode(v.str("salt_hex"))
        val encoded = OffloadDeepLink.encodePairInvite(v.str("relay_base"), v.str("session"), salt)
        assertEquals(v.str("uri"), encoded, "Kotlin invite encode must be byte-identical to Go's")

        val parsed = OffloadDeepLink.parsePairInvite(v.str("uri"))
        assertEquals(v.str("relay_base"), parsed.relayBase)
        assertEquals(v.str("session"), parsed.session)
        assertTrue(salt.contentEquals(parsed.salt))
    }

    @Test
    fun gen1OffloadLinksAreRefused() {
        // ADR-0022: `offload-pair` and `unwrap` moved to the `void-which-binds:` scheme with
        // the rest of the URI surface; a `voidbind:` link is refused, not dual-parsed.
        val gen1Invite = section("invite").str("uri").replaceFirst("void-which-binds:", "voidbind:")
        assertFailsWith<IllegalArgumentException> { OffloadDeepLink.parsePairInvite(gen1Invite) }
        val ping = OffloadDeepLink.encodeWakePing("https://relay.example/pair", "s1")
        assertTrue(ping.startsWith("void-which-binds:unwrap?"), ping)
        assertEquals("s1", OffloadDeepLink.parseWakePing(ping).session)
        assertFailsWith<IllegalArgumentException> {
            OffloadDeepLink.parseWakePing(ping.replaceFirst("void-which-binds:", "voidbind:"))
        }
    }

    @Test
    fun pairingConfirmTranscriptAndSignaturesAndSas() {
        val v = section("pairing_confirm")
        val salt = v.bytes("salt_hex")
        val transportPub = v.bytes("transport_pub_hex")
        val phonePub = v.bytes("phone_pub_hex")
        val phoneEnc = v.bytes("phone_enc_hex")

        val transcript = OffloadProtocol.pairConfirmTranscript(v.str("session"), salt, transportPub, phonePub, phoneEnc)
        assertEquals(v.str("transcript_hex"), Hex.encode(transcript), "confirm transcript must match Go byte-for-byte")

        val verifier = Ed25519Engine.verifier()
        assertTrue(
            verifier.verify(transportPub, transcript, v.bytes("transport_sig_hex")),
            "desktop confirm sig must verify",
        )
        assertTrue(verifier.verify(phonePub, transcript, v.bytes("phone_sig_hex")), "phone confirm sig must verify")

        // The SAS the human compares — derived by the shared Pairing primitive with
        // the desktop (transport key) as initiator and the phone as responder.
        val sas = Pairing.deriveSas(Pairing.Keys(transportPub), Pairing.Keys(phonePub, phoneEnc), salt)
        assertEquals(v.str("sas"), sas, "offload pairing SAS must match Go's pairing.Derive")
    }

    @Test
    fun unwrapRequestSigningInputAndVerify() {
        val v = section("unwrap_request")
        val input = OffloadProtocol.requestSigningInput(
            v.bytes("wrapped_hex"),
            v.bytes("eph_pub_hex"),
            v.bytes("nonce_hex"),
        )
        assertEquals(v.str("signing_input_hex"), Hex.encode(input), "request signing input must match Go")

        val req = OffloadProtocol.verifyRequest(
            Ed25519Engine.verifier(),
            v.bytes("transport_pub_hex"),
            v.bytes("request_hex"),
        )
        assertTrue(req.wrapped.contentEquals(v.bytes("wrapped_hex")))
        assertTrue(req.ephPub.contentEquals(v.bytes("eph_pub_hex")))
        assertTrue(req.nonce.contentEquals(v.bytes("nonce_hex")))
    }

    @Test
    fun unwrapResponseSigningInputAndVerify() {
        val v = section("unwrap_response")
        val input = OffloadProtocol.responseSigningInput(v.bytes("nonce_hex"), v.bytes("sealed_hex"))
        assertEquals(v.str("signing_input_hex"), Hex.encode(input), "response signing input must match Go")

        val resp = OffloadProtocol.verifyResponse(
            Ed25519Engine.verifier(),
            v.bytes("phone_pub_hex"),
            v.bytes("nonce_hex"),
            v.bytes("response_hex"),
        )
        assertTrue(resp.sealed.contentEquals(v.bytes("sealed_hex")))
    }

    @Test
    fun forgedRequestIsRefused() {
        val v = section("unwrap_request")
        val raw = v.bytes("request_hex")
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0xFF).toByte() // corrupt the signature
        assertFailsWith<OffloadProtocol.OffloadWireException> {
            OffloadProtocol.verifyRequest(Ed25519Engine.verifier(), v.bytes("transport_pub_hex"), raw)
        }
    }

    @Test
    fun phoneOpensAGoSealedSpaceKey() {
        // The interop proof: a space key the DESKTOP (Go) sealed to the phone's
        // encryption key must unwrap here, and its EncryptChange canary must decrypt —
        // so the phone can open what the desktop wraps (ADR-0098 §4).
        val v = section("seal_interop")
        val spaceKey = VoidbindEncryption.unwrap(v.bytes("wrapped_hex"), v.bytes("recipient_seed_hex"))
        val plain = VoidbindEncryption.decryptChange(spaceKey, v.bytes("canary_ct_hex"))
        assertTrue(plain.contentEquals(v.bytes("canary_plain_hex")), "phone must recover the Go-sealed canary")
    }

    @Test
    fun phoneResealRoundTripsToADesktopEphemeralKey() {
        // The phone side of a real unwrap: given a space key, seal it to the desktop's
        // per-unwrap ephemeral key and sign the response; the desktop opens it. Here
        // both halves use the Kotlin crypto (the Go→Kotlin direction is pinned above;
        // the live cross-direction round-trip is phone-gated).
        val spaceKey = VoidbindEncryption.newSpaceKey()
        val ephSeed = ByteArray(32) { 0x44 }
        val ephPub = one.rarebit.voidwhichbinds.crypto.X25519.scalarMultBase(ephSeed)
        val sealed = VoidbindEncryption.seal(spaceKey, ephPub)
        val opened = VoidbindEncryption.unwrap(sealed, ephSeed)
        assertTrue(opened.contentEquals(spaceKey), "the sealed space key must reopen with the ephemeral seed")
    }
}
