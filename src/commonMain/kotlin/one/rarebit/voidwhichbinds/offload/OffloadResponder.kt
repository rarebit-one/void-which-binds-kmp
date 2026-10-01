package one.rarebit.voidwhichbinds.offload

import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption

/**
 * The phone's RESPONDER logic for the cruciform-offload exchanges (ADR-0098),
 * sequencing the [OffloadProtocol] wire over a relay. It is pure Kotlin: the relay
 * is an [OffloadTransport] seam (voidbind's `net.RelayClient` for role `responder`
 * satisfies it in the app; a fake drives it in tests), the device keys are the
 * [Ed25519Signer]/[Ed25519Verifier] seams, and the encryption key is passed as a
 * seed the caller unlocks behind the biometric gate. What is NOT here — the QR
 * scanner, the UnifiedPush receive / LAN accept that DELIVER an invite or a wake,
 * the biometric prompt itself, and the enclave that guards the seed — is the app's
 * device-gated wiring.
 *
 * The desktop is the initiator; the phone posts its own role's slots and fetches
 * the desktop's, so neither side deadlocks (each posts before it fetches).
 */

/** The relay slot names the offload exchanges use (heyarr-core RelayPair/UnwrapTypes). */
public object OffloadSlots {
    public const val COMMIT: String = "commit"
    public const val REVEAL: String = "reveal"
    public const val CONFIRM: String = "confirm"
    public const val UNWRAP_REQ: String = "unwrap-req"
    public const val UNWRAP_RESP: String = "unwrap-resp"
}

/** One relay session, from the phone's (responder) point of view. */
public interface OffloadTransport {
    /** Write this responder's [type] slot (write-once). */
    public fun post(type: String, payload: ByteArray)

    /** Poll the desktop's (initiator) [type] slot until present, returning its bytes. */
    public fun fetch(type: String): ByteArray
}

/**
 * The phone side of the one-time pairing. Split into [handshake] (derive the SAS,
 * pin nothing) and [confirm] (exchange proof-of-possession, then pin) so the human
 * SAS/number-match gate sits between them: a caller that never calls [confirm]
 * pins nobody.
 */
public class OffloadPairingResponder(
    private val deviceSigner: Ed25519Signer,
    private val devicePub: ByteArray,
    private val deviceEnc: ByteArray,
    private val verifier: Ed25519Verifier,
) {
    /** What [handshake] learned: the desktop's transport key and the SAS to compare. */
    public class Handshaken(public val transportPub: ByteArray, public val sas: String)

    /**
     * Run commit → reveal → open → derive and return the SAS. Signs and pins
     * nothing: the commitment is posted and the desktop's fetched before any key is
     * revealed, and the desktop's commitment is opened against its revealed key
     * before the SAS is derived.
     */
    public fun handshake(t: OffloadTransport, invite: OffloadDeepLink.PairInvite): Handshaken {
        t.post(OffloadSlots.COMMIT, Pairing.commit(devicePub, deviceEnc))
        val desktopCommit = t.fetch(OffloadSlots.COMMIT)

        t.post(OffloadSlots.REVEAL, OffloadProtocol.encodePhoneReveal(devicePub, deviceEnc).encodeToByteArray())
        val transportPub = OffloadProtocol.parseDesktopRevealSign(t.fetch(OffloadSlots.REVEAL).decodeToString())

        require(Pairing.opens(desktopCommit, transportPub)) {
            "desktop commitment does not open against its revealed key"
        }
        val sas = Pairing.deriveSas(Pairing.Keys(transportPub), Pairing.Keys(devicePub, deviceEnc), invite.salt)
        return Handshaken(transportPub, sas)
    }

    /**
     * After the human confirms the SAS matched, sign the transcript with the device
     * key (proof-of-possession + consent), post it, and verify the desktop's — so a
     * side that never confirms pins nobody. Returns the transport key to pin as the
     * paired terminal.
     */
    public fun confirm(t: OffloadTransport, invite: OffloadDeepLink.PairInvite, h: Handshaken): ByteArray {
        val transcript = OffloadProtocol.pairConfirmTranscript(
            invite.session,
            invite.salt,
            h.transportPub,
            devicePub,
            deviceEnc,
        )
        t.post(OffloadSlots.CONFIRM, OffloadProtocol.encodeConfirm(deviceSigner.sign(transcript)).encodeToByteArray())

        val desktopSig = OffloadProtocol.parseConfirmSig(t.fetch(OffloadSlots.CONFIRM).decodeToString())
        require(verifier.verify(h.transportPub, transcript, desktopSig)) {
            "desktop pairing confirmation does not verify against its transport key"
        }
        return h.transportPub
    }
}

/**
 * The phone side of a recurring unwrap. Given a woken relay session, it fetches the
 * desktop's signed request, verifies it against the pinned transport key, unwraps
 * the space key with the device encryption key, reseals it to the desktop's
 * per-unwrap ephemeral key, and posts the signed reply. The space key lands in
 * memory here — that is ADR-0098 §4 by design; what offload protects is the
 * long-term device key, which never leaves the phone.
 *
 * [deviceEncSeed] is the X25519 encryption seed the caller unlocks behind the
 * biometric gate (TPM/StrongBox speak P-256, not Curve25519, so the seed is
 * hardware-GATED, not enclave-native — ADR-0098 §2/ADR-0001). Zero it after use.
 */
public class OffloadUnwrapResponder(
    private val deviceSigner: Ed25519Signer,
    private val deviceEncSeed: ByteArray,
    private val pinnedTransportPub: ByteArray,
    private val verifier: Ed25519Verifier,
) {
    /** Serve exactly one unwrap over the given (already-woken) relay session. */
    public fun serveOnce(t: OffloadTransport) {
        val req = OffloadProtocol.verifyRequest(verifier, pinnedTransportPub, t.fetch(OffloadSlots.UNWRAP_REQ))
        val spaceKey = VoidbindEncryption.unwrap(req.wrapped, deviceEncSeed)
        val sealed = VoidbindEncryption.seal(spaceKey, req.ephPub)
        t.post(OffloadSlots.UNWRAP_RESP, OffloadProtocol.signResponse(deviceSigner, req.nonce, sealed))
    }
}
