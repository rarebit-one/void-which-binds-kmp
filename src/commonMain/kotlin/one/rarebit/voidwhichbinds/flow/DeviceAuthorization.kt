package one.rarebit.voidwhichbinds.flow

import dev.whyoleg.cryptography.random.CryptographyRandom
import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.Invite
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.PairflowAuthority
import one.rarebit.voidwhichbinds.net.PairflowInitiator
import one.rarebit.voidwhichbinds.net.RelayClient

/**
 * The **existing device authorising a new one**, as one app flow (the mirror of
 * [DevicePairing]). Under ADR-0005 / void-which-binds-go ADR-0007 this device is ANY
 * member of the identity — it signs the new device's add op with its own hardware
 * key, citing the heads of the membership ops it holds; no recovery secret is
 * involved. (The genesis form — the recovery key itself — survives for the first
 * device and for re-admitting a removed device, which only genesis can do.)
 *
 * It opens a relay session, shows the new device a `void-which-binds:pair?…` invite QR
 * (v4, carrying the identity), runs the commit-before-reveal handshake, displays
 * the 7-digit SAS, and — only after the human confirms both screens match — signs
 * the add op, seals it with the ops to the new device's X25519 key, and posts it.
 *
 * Three steps around the human gate:
 *  1. [invite] opens the session + returns the [Invitation.inviteQr] to render.
 *  2. [handshake] runs once the new device joins → the SAS to compare.
 *  3. [authorise] (only after the human matches the SAS) signs + seals + delivers,
 *     and returns the ops this device now holds (including the add it just signed)
 *     for the app to record in its replica.
 *
 * Blocking (the relay is polled); run it off the main thread. [clock] supplies
 * unix seconds (`commonMain` has no clock) for the op's issued-at.
 */
class DeviceAuthorization private constructor(
    private val http: HttpTransport,
    private val authority: () -> PairflowAuthority,
    private val clock: () -> Long,
    private val pollIntervalMillis: Long,
    /**
     * How long [handshake] waits for the new device to join the relay before it fails
     * with [PairingFailureKind.TIMEOUT]. The new device may have to be created first
     * (a key behind a fingerprint, on another app), so an app should pass the relay's
     * session TTL here rather than the transport-sized default.
     */
    private val maxWaitMillis: Long,
) {
    /**
     * A MEMBER device authorising: [device] holds the hardware signing key and the
     * encryption keys, [admittingOp] is its own admitting op (the cert/op it
     * presents as its credential) and [knownOps] the membership replica it holds.
     * Refuses (at [invite]) a device its own ops do not find a member.
     */
    constructor(
        http: HttpTransport,
        device: DeviceIdentity,
        admittingOp: String,
        knownOps: List<String>,
        clock: () -> Long,
        pollIntervalMillis: Long = 150,
        maxWaitMillis: Long = RelayClient.DEFAULT_MAX_WAIT_MILLIS,
    ) : this(
        http,
        {
            PairflowAuthority.Device(
                device.asSigner(),
                device.signPublicKey,
                device.encPublicKey,
                admittingOp,
                knownOps,
            )
        },
        clock,
        pollIntervalMillis,
        maxWaitMillis,
    )

    /**
     * GENESIS authorising: this device holds the user identity (the recovery
     * secret's key). Used for the first device and for recovery re-adds; [knownOps]
     * must include the remove being overridden for a re-add to be honoured.
     */
    constructor(
        http: HttpTransport,
        identity: UserIdentity,
        clock: () -> Long,
        certLifetimeSeconds: Long = Enrolment.DEFAULT_LIFETIME_SECONDS,
        pollIntervalMillis: Long = 150,
        knownOps: List<String> = emptyList(),
        maxWaitMillis: Long = RelayClient.DEFAULT_MAX_WAIT_MILLIS,
    ) : this(
        http,
        { PairflowAuthority.Genesis(identity.signer(), identity.userPublicKey, knownOps, certLifetimeSeconds) },
        clock,
        pollIntervalMillis,
        maxWaitMillis,
    )

    /** An opened pairing session: the [inviteQr] to render + the state the later steps resume. */
    class Invitation internal constructor(
        val inviteQr: String,
        val relaySession: String,
        internal val initiator: PairflowInitiator,
        /** The relay this invitation lives on — named in a `*Catching` failure. */
        internal val relayBase: String = "",
    ) {
        /** The identity being enrolled into (`ed25519:<hex>`). */
        val userId: String get() = initiator.userId

        /**
         * The new device's signing key (`ed25519:<hex>`) once [handshake] has opened the
         * responder's commitment; null before that. Used by the same-phone one-tap path
         * (ADR-0008) to check the key a relying-party app on THIS phone reports over the
         * local intent channel against the one the relay revealed.
         */
        val responderDeviceId: String? get() = initiator.responderDeviceId
    }

    /**
     * Open a relay session and render the invite QR. A fresh random [salt] is drawn
     * per pairing (freshness for the SAS); pass one only to pin it in a test.
     */
    @Throws(Exception::class)
    fun invite(relayBase: String, salt: ByteArray = randomSalt()): Invitation {
        val now = clock()
        // Build the initiator FIRST: a member device that is not (any more) a member
        // under its own ops is refused here, before a session is opened.
        val auth = authority()
        val session = RelayClient.createSession(http, relayBase)
        val relay = RelayClient(http, relayBase, session, RelayClient.ROLE_INITIATOR, pollIntervalMillis, maxWaitMillis)
        val initiator = PairflowInitiator(relay, auth, salt, now)
        return Invitation(Invite.encode(relayBase, session, salt, initiator.userId), session, initiator, relayBase)
    }

    /**
     * Like [invite], but a relay that cannot be reached (no route, refused, TLS, timeout,
     * cleartext-blocked) or that refuses to open a session resolves to a
     * [PairingOutcome.Failed] the caller renders — it never throws, so the "Add a
     * device" tap cannot crash the app when the phone has no route to the relay.
     */
    fun inviteCatching(relayBase: String, salt: ByteArray = randomSalt()): PairingOutcome<Invitation> =
        PairingFailures.catching(relayBase) { invite(relayBase, salt) }

    /**
     * Like [handshake], but a transport failure, a relay refusal, an invite that expires
     * unjoined ([PairingFailureKind.TIMEOUT]) or a commitment that does not open resolves
     * to a [PairingOutcome.Failed] instead of throwing.
     */
    fun handshakeCatching(invitation: Invitation): PairingOutcome<String> =
        PairingFailures.catching(invitation.relayBase) { handshake(invitation) }

    /**
     * Like [authorise], but a transport failure or relay refusal while delivering the
     * sealed admission resolves to a [PairingOutcome.Failed] instead of throwing.
     */
    fun authoriseCatching(invitation: Invitation): PairingOutcome<List<String>> =
        PairingFailures.catching(invitation.relayBase) { authorise(invitation) }

    /** Run the handshake once the new device joins; return the SAS to compare. */
    @Throws(Exception::class)
    fun handshake(invitation: Invitation): String = invitation.initiator.handshake()

    /**
     * After the human confirms the SAS: sign, seal, and deliver the add op. Returns
     * the membership ops this device now holds — its replica plus the add it just
     * signed — for the app to persist.
     */
    @Throws(Exception::class)
    fun authorise(invitation: Invitation): List<String> {
        invitation.initiator.authorise()
        return invitation.initiator.ops
    }

    /**
     * The human said the strings DIFFER (or cancelled): tell the new device, so it stops
     * waiting instead of timing out (void-which-binds-go ADR-0012). Signs a refusal with this
     * device's key — on a hardware keystore that is the same biometric gate as
     * [authorise] — and posts it. Admits nobody; [authorise] fails afterwards.
     */
    @Throws(Exception::class)
    fun refuse(invitation: Invitation) {
        invitation.initiator.refuse()
    }

    /**
     * Like [refuse], but a failure to deliver the refusal (no route, a relay without the
     * `refuse` slot) resolves to a [PairingOutcome.Failed] instead of throwing. The
     * pairing is abandoned either way; the new device then just times out.
     */
    fun refuseCatching(invitation: Invitation): PairingOutcome<Unit> =
        PairingFailures.catching(invitation.relayBase) { refuse(invitation) }

    private companion object {
        /** 32 bytes of salt — comfortably above [Pairing.MIN_SALT_LEN]. */
        fun randomSalt(): ByteArray = CryptographyRandom.Default.nextBytes(maxOf(32, Pairing.MIN_SALT_LEN))
    }
}
