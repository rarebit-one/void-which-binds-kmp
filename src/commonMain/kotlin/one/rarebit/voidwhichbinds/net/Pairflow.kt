package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Labels
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.PairRefusal
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.PairingRefusedException
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * Device-side pairing over an untrusted relay (void-which-binds-go `pairflow`, v0.9.0 /
 * ADR-0007): the two-sided commit-before-reveal handshake, with the human gate and
 * the membership gate.
 *
 * [PairflowInitiator] is an existing **member** device (any device the identity's
 * membership currently admits — or, for the first device and recovery, the genesis
 * key); [PairflowResponder] is the new device. Each side runs [handshake] — commit,
 * fetch the peer commit BEFORE revealing, reveal, OPEN the peer commitment, then
 * derive the SAS — and returns the string a human compares. The initiator's reveal
 * also carries the membership ops it knows; the responder EVALUATES them under the
 * invite's identity and requires the revealed signing key to be a member (or
 * genesis) BEFORE it derives any SAS — a non-member never gets a string to be
 * compared. Handshake signs nothing; only [PairflowInitiator.authorise] signs +
 * hands over the add op, and only [PairflowResponder.receive] takes it in, so the
 * human comparison gates enrolment.
 *
 * The relay envelope is byte-identical to void-which-binds-go: the `reveal` is
 * `{"sign":"ed25519:<hex>"[,"enc":"x25519:<hex>"][,"ops":[…]]}`, and the `cert`
 * message is `{"wrapped":"<b64url>","cipher":"<b64url>"}` — a space key sealed to
 * the responder's X25519 key plus the ADMISSION `{"op":…,"ops":[…]}` encrypted under
 * it. The X25519 SEAL/UNSEAL crypto ([CertSealer]) is implemented by
 * [VoidbindCertSealer] (void-which-binds-go/encryption, byte-for-byte, KAT-verified).
 *
 * Instead of authorising, the initiator may [PairflowInitiator.refuse] (void-which-binds-go
 * ADR-0012): a [PairRefusal] signed by its key and bound to the session salt, posted to
 * the `refuse` slot. [PairflowResponder.receive] watches that slot while it waits for
 * the cert and throws [PairingRefusedException] for a refusal that verifies, instead of
 * timing out; anything else there is ignored.
 */

/** The X25519-sealed admission as it crosses the relay. */
class SealedCert(val wrapped: ByteArray, val cipher: ByteArray)

/**
 * Seals/opens the admission plaintext to a device's X25519 encryption key. The
 * production implementation is [VoidbindCertSealer] (ephemeral-static ECDH seal +
 * XChaCha20-Poly1305, byte-identical to void-which-binds-go/encryption).
 */
interface CertSealer {
    fun seal(certToken: String, recipientEncPub: ByteArray): SealedCert
    fun open(sealed: SealedCert, recipientEncPriv: ByteArray): String
}

/**
 * What a responder ends a pairing holding: its admitting [op] (the credential it
 * presents) and the membership [ops] that authorise it (its replica) — everything
 * an app persists. Mirrors void-which-binds-go `pairflow.Enrolment`.
 */
class Admission(val op: String, val ops: List<String>)

private fun revealJson(signRendered: String, encRendered: String?, ops: List<String>): ByteArray {
    val fields = mutableListOf<Pair<String, Any>>("sign" to signRendered)
    if (!encRendered.isNullOrEmpty()) fields.add("enc" to encRendered)
    if (ops.isNotEmpty()) fields.add("ops" to ops)
    return MiniJson.encodeObject(fields).encodeToByteArray()
}

private class Reveal(val sign: ByteArray, val enc: ByteArray, val ops: List<String>)

private fun parseReveal(bytes: ByteArray): Reveal {
    val obj = MiniJson.parseObject(bytes.decodeToString())
    val sign = KeyRef.parse(obj["sign"] as String).bytes
    val encStr = obj["enc"] as? String
    val enc = if (encStr.isNullOrEmpty()) ByteArray(0) else KeyRef.parse(encStr).bytes
    val ops = (obj["ops"] as? List<*>)?.map { it as String } ?: emptyList()
    return Reveal(sign, enc, ops)
}

/**
 * The initiator's authority: a MEMBER device (the ordinary case — no secret
 * anywhere) or the GENESIS key (the first device, and re-admitting a removed
 * device, which only genesis can do). Mirrors void-which-binds-go's two constructors
 * (`NewDeviceInitiator` / `NewGenesisInitiator`).
 */
sealed class PairflowAuthority {
    /** This device: its signing key (hardware-held; signs only), its keys, its admitting op and replica. */
    class Device(
        val signer: Ed25519Signer,
        val signPublicKey: ByteArray,
        val encPublicKey: ByteArray,
        val admittingOp: String,
        val knownOps: List<String>,
    ) : PairflowAuthority()

    /** The genesis key (derived from the recovery secret) plus the ops it knows. */
    class Genesis(
        val signer: Ed25519Signer,
        val publicKey: ByteArray,
        val knownOps: List<String>,
        val lifetimeSeconds: Long,
    ) : PairflowAuthority()
}

class PairflowInitiator(
    private val relay: RelayClient,
    authority: PairflowAuthority,
    private val salt: ByteArray,
    /** Unix seconds: the membership is evaluated and the add op issued at this instant. */
    private val now: Long,
) {
    private val signer: Ed25519Signer
    private val signPub: ByteArray

    /** Empty for genesis (the recovery key has no encryption key). */
    private val encPub: ByteArray
    private val lifetimeSeconds: Long

    /** The identity being enrolled into (`ed25519:<hex>`) — what the invite carries. */
    val userId: String

    /** The membership ops this initiator holds; after [authorise], includes the add it signed. */
    var ops: List<String>
        private set

    private var respSign: ByteArray = ByteArray(0)
    private var respEnc: ByteArray = ByteArray(0)
    private var handshook = false

    // A pairing ends admitted or refused, never both.
    private var authorised = false
    private var refused = false

    init {
        require(salt.size >= Pairing.MIN_SALT_LEN) { "pairflow: salt is too short" }
        when (authority) {
            is PairflowAuthority.Device -> {
                require(authority.encPublicKey.size == Pairing.ENC_KEY_SIZE) {
                    "pairflow: a device encryption key is required"
                }
                val op = MembershipOp.verify(authority.admittingOp)
                val self = KeyRef.ed25519(authority.signPublicKey).render()
                require(op.device == self) { "pairflow: the admitting op admits ${op.device}, not this device" }
                val merged = Membership.merge(authority.knownOps, listOf(authority.admittingOp))
                val view = Membership.evaluate(op.user, merged, now)
                // Refuse a device its own ops do not find a member at now — the pairing
                // would end in an op no RP honours, and the responder would refuse it
                // before the SAS anyway.
                check(view.isMember(self)) {
                    "pairflow: this device is not a member of ${op.user} under the ops it holds"
                }
                signer = authority.signer
                signPub = authority.signPublicKey
                encPub = authority.encPublicKey
                userId = op.user
                ops = merged
                lifetimeSeconds = 0
            }

            is PairflowAuthority.Genesis -> {
                require(authority.publicKey.size == Pairing.ED25519_PUBLIC_KEY_SIZE) {
                    "pairflow: a user identity key is required"
                }
                signer = authority.signer
                signPub = authority.publicKey
                encPub = ByteArray(0)
                userId = KeyRef.ed25519(authority.publicKey).render()
                ops = Membership.merge(authority.knownOps)
                lifetimeSeconds = authority.lifetimeSeconds
            }
        }
    }

    /** This initiator's signing key (`ed25519:<hex>`): the member doing the admitting, or genesis. */
    val deviceId: String get() = KeyRef.ed25519(signPub).render()

    /**
     * The RESPONDER's device signing key (`ed25519:<hex>`) as the relay revealed it, or
     * null before [handshake] has opened its commitment. This is the key the add op will
     * name, and — for the same-phone one-tap path (void-which-binds-kmp ADR-0008) — the value the
     * relying-party app reports back over the local intent channel, so the two apps can
     * compare it instead of a human comparing digits. It is a public key, already
     * committed to before it was revealed; exposing it grants nothing.
     */
    val responderDeviceId: String? get() = if (respSign.isEmpty()) null else KeyRef.ed25519(respSign).render()

    /** Whether this initiator signs as the genesis key. */
    val genesis: Boolean get() = encPub.isEmpty()

    /**
     * Run the handshake and return the SAS to compare. Signs nothing. The initiator
     * presents its device keys — signing and encryption — exactly like a responder;
     * a genesis initiator's missing encryption key is framed into the commitment and
     * the SAS, so a relay that ADDS one is caught. The reveal carries [ops].
     */
    fun handshake(): String {
        val myCommit = Pairing.commit(signPub, encPub)
        relay.post("commit", myCommit)
        val peerCommit = relay.fetch("commit")

        relay.post("reveal", revealJson(deviceId, if (genesis) null else KeyRef.x25519(encPub).render(), ops))
        val peer = parseReveal(relay.fetch("reveal"))
        require(peer.enc.size == Pairing.ENC_KEY_SIZE) { "pairflow: responder must reveal an encryption key" }
        require(Pairing.opens(peerCommit, peer.sign, peer.enc)) {
            "pairflow: responder commitment does not open (rushing attacker)"
        }
        val sas = Pairing.deriveSas(
            Pairing.Keys(signPub, encPub),
            Pairing.Keys(peer.sign, peer.enc),
            salt,
        )
        respSign = peer.sign
        respEnc = peer.enc
        handshook = true
        return sas
    }

    /**
     * After the human confirms the SAS: sign the add op for the responder's keys —
     * by this device, citing the current heads of the ops it holds — seal the
     * admission (the op + the ops) to the responder's encryption key, and post it.
     * The signed op joins [ops] so the caller can record it in its replica.
     */
    fun authorise(sealer: CertSealer = VoidbindCertSealer) {
        check(handshook) { "pairflow: authorise before a successful handshake" }
        check(!refused) { "pairflow: authorise after refuse" }
        val view = Membership.evaluate(userId, ops, now)
        val opToken = MembershipOp.sign(
            signer, signPub, userId, MembershipOp.Kind.ADD,
            dev = KeyRef.ed25519(respSign).render(),
            deviceEnc = KeyRef.x25519(respEnc).render(),
            prev = view.heads,
            issuedAt = now,
            lifetimeSeconds = lifetimeSeconds,
        )
        ops = Membership.merge(ops, listOf(opToken))
        authorised = true
        val admission = MiniJson.encodeObject(
            buildList<Pair<String, Any>> {
                add("op" to opToken)
                if (ops.isNotEmpty()) add("ops" to ops)
            },
        )
        val sealed = sealer.seal(admission, respEnc)
        val msg = MiniJson.encodeObject(
            listOf(
                "wrapped" to Base64Url.encode(sealed.wrapped),
                "cipher" to Base64Url.encode(sealed.cipher),
            ),
        )
        relay.post("cert", msg.encodeToByteArray())
    }

    /**
     * Tell the new device the pairing is refused (void-which-binds-go ADR-0012) — the human said
     * the strings differ, or cancelled. Posts a [PairRefusal] signed by this initiator's
     * key and bound to the session salt; a responder waiting in [PairflowResponder.receive]
     * stops at once. Signs no op and admits nobody. Mirrors void-which-binds-go
     * `Initiator.Refuse`.
     *
     * It fails after [authorise], and [authorise] fails after it. The post is advisory: a
     * relay without the `refuse` slot answers 400 ([RelayHttpException]) and an older
     * responder never reads it — either way it simply times out, as before.
     *
     * The signer is this device's key, so on a hardware keystore signing the refusal
     * passes the same biometric gate as [authorise].
     */
    fun refuse() {
        check(!authorised) { "pairflow: refuse after authorise" }
        val token = PairRefusal.sign(signer, signPub, salt)
        refused = true
        relay.post(PairRefusal.SLOT, token.encodeToByteArray())
    }
}

class PairflowResponder(
    private val relay: RelayClient,
    /** The identity (`ed25519:<hex>`) from the invite — what the initiator must be a member of. */
    private val userId: String,
    private val deviceSignPub: ByteArray,
    private val deviceEncPub: ByteArray,
    private val salt: ByteArray,
    /** Unix seconds: the clock the membership is evaluated against. */
    private val now: Long,
) {
    // The responder SIGNS NOTHING during pairing — it commits + reveals its public
    // keys and receives an op the initiator signs. So no device signing SEED is
    // taken here: a hardware DeviceKeyStore never exposes one, and this flow does
    // not need it. Possession of the device key is proven later (at login/use).
    private var initSign: ByteArray = ByteArray(0)
    private var initOps: List<String> = emptyList()
    private var handshook = false

    init {
        val ref = KeyRef.parse(userId)
        require(ref.alg == Labels.ALG_ED25519 && ref.bytes.size == 32) { "pairflow: invite user is not an ed25519 key" }
        require(salt.size >= Pairing.MIN_SALT_LEN) { "pairflow: salt is too short" }
    }

    val deviceId: String get() = KeyRef.ed25519(deviceSignPub).render()
    val deviceEncId: String get() = KeyRef.x25519(deviceEncPub).render()

    /**
     * Run the handshake and return the SAS to compare. Symmetric to the initiator's;
     * then — before any SAS exists — the initiator's revealed ops are evaluated under
     * the invite's identity and its signing key must be a member (or the genesis key
     * itself). A non-member gets no string: there is nothing for a human to be
     * talked into confirming.
     */
    fun handshake(): String {
        val myCommit = Pairing.commit(deviceSignPub, deviceEncPub)
        relay.post("commit", myCommit)
        val peerCommit = relay.fetch("commit")

        relay.post("reveal", revealJson(deviceId, deviceEncId, emptyList()))
        val peer = parseReveal(relay.fetch("reveal"))
        // The commitment was made over exactly what was revealed — a member's
        // (sign, enc) or genesis's (sign, empty) — so open it the same way.
        require(Pairing.opens(peerCommit, peer.sign, peer.enc)) {
            "pairflow: initiator commitment does not open"
        }

        // MEMBERSHIP GATE, before any SAS.
        val initId = KeyRef.ed25519(peer.sign).render()
        if (initId != userId) {
            require(peer.enc.isNotEmpty()) { "pairflow: a member initiator must reveal an encryption key" }
            val view = Membership.evaluate(userId, peer.ops, now)
            check(view.isMember(initId)) { "pairflow: initiator $initId is not a member of $userId — no SAS derived" }
        }

        val sas = Pairing.deriveSas(
            Pairing.Keys(peer.sign, peer.enc),
            Pairing.Keys(deviceSignPub, deviceEncPub),
            salt,
        )
        initSign = peer.sign
        initOps = peer.ops
        handshook = true
        return sas
    }

    /**
     * After the human confirms: receive the sealed admission, unseal it with the
     * device encryption key, and re-evaluate it — the op must be an add of THIS
     * device's keys, signed by the initiator whose key is bound in the SAS, and
     * evaluating the ops it came with must find this device a member of the invite's
     * identity. Returns the [Admission] to persist.
     *
     * While it waits it also watches the initiator's `refuse` slot (void-which-binds-go
     * ADR-0012): a [PairRefusal] signed by the SAS-bound initiator for this session
     * throws [PairingRefusedException] at once. Anything else there — a forgery, another
     * session's refusal, a relay without the slot — is ignored and the wait goes on.
     */
    fun receive(deviceEncPriv: ByteArray, sealer: CertSealer = VoidbindCertSealer): Admission {
        check(handshook) { "pairflow: receive before a successful handshake" }
        val cert = relay.fetchWatching("cert", PairRefusal.SLOT) { refusal ->
            if (PairRefusal.verify(refusal.decodeToString(), initSign, salt)) throw PairingRefusedException()
        }
        val obj = MiniJson.parseObject(cert.decodeToString())
        val sealed = SealedCert(
            Base64Url.decode(obj["wrapped"] as String),
            Base64Url.decode(obj["cipher"] as String),
        )
        val plain = sealer.open(sealed, deviceEncPriv)
        val adm = MiniJson.parseObject(plain)
        val opToken = adm["op"] as? String ?: throw IllegalArgumentException("pairflow: admission carries no op")
        val admOps = (adm["ops"] as? List<*>)?.map { it as String } ?: emptyList()

        val op = MembershipOp.verify(opToken)
        require(op.kind == MembershipOp.Kind.ADD && op.user == userId) {
            "pairflow: received a ${op.kind.wire} for ${op.user}, want an add for $userId"
        }
        require(op.by == KeyRef.ed25519(initSign).render()) {
            "pairflow: op signed by ${op.by}, not the initiator bound in the SAS"
        }
        require(op.device == deviceId) { "pairflow: op admits device ${op.device}, not this device $deviceId" }
        require(op.deviceEnc == deviceEncId) {
            "pairflow: op binds encryption key ${op.deviceEnc}, not this device's $deviceEncId"
        }
        val ops = Membership.merge(initOps, admOps, listOf(opToken))
        val view = Membership.evaluate(userId, ops, now)
        view.rejected[op.hash]?.let { throw IllegalStateException("pairflow: the received op is rejected: $it") }
        view.ineffective[op.hash]?.let {
            throw IllegalStateException("pairflow: the received op does not admit this device: $it")
        }
        check(view.isMember(deviceId)) { "pairflow: this device is not a member of $userId after the admission" }
        return Admission(opToken, ops)
    }
}
