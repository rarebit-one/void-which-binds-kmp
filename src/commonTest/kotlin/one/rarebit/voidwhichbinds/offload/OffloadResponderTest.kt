package one.rarebit.voidwhichbinds.offload

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption
import one.rarebit.voidwhichbinds.crypto.X25519
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The phone RESPONDER driven against a scripted desktop initiator over an in-memory
 * relay — the offload pairing + unwrap flows end to end, with real Ed25519/X25519
 * and the real [OffloadProtocol] wire, only the transport and the human faked. It
 * proves both sides derive the same SAS and pin each other, and that the phone
 * opens a space key wrapped to it and reseals it to the desktop's ephemeral key so
 * the desktop recovers it — the live path minus the device.
 */
class OffloadResponderTest {

    /** An in-memory, role-separated, write-once relay (like heyarr-core's memRelay). */
    private class FakeRelay {
        val slots = HashMap<String, ByteArray>()
        fun view(me: String, peer: String) = object : OffloadTransport {
            override fun post(type: String, payload: ByteArray) {
                require(slots.put("$me:$type", payload) == null) { "double post $me:$type" }
            }
            override fun fetch(type: String): ByteArray = slots["$peer:$type"] ?: error("no $peer:$type staged")
        }
    }

    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }

    @Test
    fun pairingRoundTripPinsBothSidesWithOneSas() {
        val transport = Ed25519Engine.generate()
        val phone = Ed25519Engine.generate()
        val phoneEncSeed = ByteArray(32) { 0x33 }
        val phoneEnc = X25519.scalarMultBase(phoneEncSeed)
        val salt = ByteArray(16) { 0x55 }
        val invite = OffloadDeepLink.PairInvite("https://relay.example/pair", "sess-1", salt)

        val relay = FakeRelay()
        // The scripted desktop (initiator) stages its commit + reveal (it commits to
        // its transport signing key, no encryption key).
        relay.slots["initiator:commit"] = Pairing.commit(transport.publicKey)
        relay.slots["initiator:reveal"] =
            MiniJson.encodeObject(listOf("sign" to KeyRef.ed25519(transport.publicKey).render())).encodeToByteArray()

        val responder =
            OffloadPairingResponder(signer(phone.privateSeed), phone.publicKey, phoneEnc, Ed25519Engine.verifier())
        val h = responder.handshake(relay.view("responder", "initiator"), invite)

        // The desktop opens the phone's commitment and derives the SAME SAS.
        assertTrue(
            Pairing.opens(relay.slots["responder:commit"]!!, phone.publicKey, phoneEnc),
            "desktop opens phone commit",
        )
        val desktopSas = Pairing.deriveSas(
            Pairing.Keys(transport.publicKey),
            Pairing.Keys(phone.publicKey, phoneEnc),
            salt,
        )
        assertTrue(desktopSas == h.sas, "both sides derive one SAS")

        // Human matched → the desktop stages its confirm; the phone confirms and pins.
        val transcript = OffloadProtocol.pairConfirmTranscript(
            invite.session,
            salt,
            transport.publicKey,
            phone.publicKey,
            phoneEnc,
        )
        relay.slots["initiator:confirm"] =
            OffloadProtocol.encodeConfirm(Ed25519Engine.sign(transport.privateSeed, transcript)).encodeToByteArray()

        val pinned = responder.confirm(relay.view("responder", "initiator"), invite, h)
        assertTrue(pinned.contentEquals(transport.publicKey), "phone pins the desktop transport key")

        // The desktop verifies the phone's confirmation (mutual proof-of-possession).
        val phoneSig = OffloadProtocol.parseConfirmSig(relay.slots["responder:confirm"]!!.decodeToString())
        assertTrue(Ed25519Engine.verify(phone.publicKey, transcript, phoneSig), "desktop verifies phone confirm")
    }

    @Test
    fun pairingRefusesADesktopThatDidNotCommitToItsRevealedKey() {
        val transport = Ed25519Engine.generate()
        val wrong = Ed25519Engine.generate()
        val phone = Ed25519Engine.generate()
        val phoneEncSeed = ByteArray(32) { 0x33 }
        val phoneEnc = X25519.scalarMultBase(phoneEncSeed)
        val invite = OffloadDeepLink.PairInvite("r", "s", ByteArray(16) { 0x55 })

        val relay = FakeRelay()
        // A relay swaps the revealed key: it commits to `transport` but reveals `wrong`.
        relay.slots["initiator:commit"] = Pairing.commit(transport.publicKey)
        relay.slots["initiator:reveal"] =
            MiniJson.encodeObject(listOf("sign" to KeyRef.ed25519(wrong.publicKey).render())).encodeToByteArray()

        val responder =
            OffloadPairingResponder(signer(phone.privateSeed), phone.publicKey, phoneEnc, Ed25519Engine.verifier())
        assertFailsWith<IllegalArgumentException> { responder.handshake(relay.view("responder", "initiator"), invite) }
    }

    @Test
    fun unwrapRoundTripReturnsTheSpaceKeySealedToTheDesktop() {
        val transport = Ed25519Engine.generate()
        val phone = Ed25519Engine.generate()
        val phoneEncSeed = ByteArray(32) { 0x33 }
        val phoneEncPub = X25519.scalarMultBase(phoneEncSeed)

        // The desktop wraps a space key TO the phone and asks it to reopen it sealed
        // to a fresh ephemeral key only this unwrap holds.
        val spaceKey = VoidbindEncryption.newSpaceKey()
        val wrapped = VoidbindEncryption.seal(spaceKey, phoneEncPub)
        val ephSeed = ByteArray(32) { 0x44 }
        val ephPub = X25519.scalarMultBase(ephSeed)
        val nonce = ByteArray(OffloadProtocol.NONCE_LEN) { 0x66 }

        val relay = FakeRelay()
        relay.slots["initiator:unwrap-req"] =
            OffloadProtocol.signRequest(signer(transport.privateSeed), wrapped, ephPub, nonce)

        OffloadUnwrapResponder(signer(phone.privateSeed), phoneEncSeed, transport.publicKey, Ed25519Engine.verifier())
            .serveOnce(relay.view("responder", "initiator"))

        // The desktop verifies the phone's reply and opens it with the ephemeral key.
        val resp = OffloadProtocol.verifyResponse(
            Ed25519Engine.verifier(),
            phone.publicKey,
            nonce,
            relay.slots["responder:unwrap-resp"]!!,
        )
        val recovered = VoidbindEncryption.unwrap(resp.sealed, ephSeed)
        assertTrue(recovered.contentEquals(spaceKey), "the desktop recovers the offloaded space key")
    }

    @Test
    fun unwrapRefusesARequestNotFromThePairedDesktop() {
        val transport = Ed25519Engine.generate()
        val attacker = Ed25519Engine.generate()
        val phone = Ed25519Engine.generate()
        val phoneEncSeed = ByteArray(32) { 0x33 }
        val wrapped = VoidbindEncryption.seal(VoidbindEncryption.newSpaceKey(), X25519.scalarMultBase(phoneEncSeed))
        val ephPub = X25519.scalarMultBase(ByteArray(32) { 0x44 })
        val nonce = ByteArray(OffloadProtocol.NONCE_LEN) { 0x66 }

        val relay = FakeRelay()
        // The request is signed by an ATTACKER key, not the pinned transport key.
        relay.slots["initiator:unwrap-req"] =
            OffloadProtocol.signRequest(signer(attacker.privateSeed), wrapped, ephPub, nonce)

        assertFailsWith<OffloadProtocol.OffloadWireException> {
            OffloadUnwrapResponder(
                signer(phone.privateSeed),
                phoneEncSeed,
                transport.publicKey,
                Ed25519Engine.verifier(),
            )
                .serveOnce(relay.view("responder", "initiator"))
        }
    }
}
