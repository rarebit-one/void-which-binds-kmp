package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The two pairing coordinators against each other through an in-memory relay, in
 * both authorities (ADR-0005):
 *
 *  - GENESIS: the recovery key ([UserIdentity]) admits the first device — the op it
 *    delivers is a genesis add with no prev.
 *  - MEMBER DEVICE: that first device (holding only its hardware key, its admitting
 *    op and its replica — no secret) admits the NEXT device; the new device receives
 *    an add signed BY the phone, citing the phone's heads, plus the ops that
 *    authorise it, and evaluating them finds both devices members.
 *
 * Plus the membership gate: a device that is NOT a member cannot even reach a SAS.
 */
class CoordinatorPairingTest {

    /** A faithful in-memory voidbind relay: opaque, write-once slots over HTTP. */
    private class RelayTransport : HttpTransport {
        private val slots = ConcurrentHashMap<String, ByteArray>()
        private var seq = 0
        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            if (url.endsWith("/v1/sessions")) {
                val id = "s${++seq}"
                return HttpResponse(200, """{"session_id":"$id"}""".encodeToByteArray())
            }
            return HttpResponse(404, ByteArray(0))
        }
        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse {
            val key = url.substringAfter("/v1/sessions/")
            return if (slots.putIfAbsent(key, body) != null) {
                HttpResponse(409, ByteArray(0))
            } else {
                HttpResponse(204, ByteArray(0))
            }
        }
        override fun get(url: String): HttpResponse {
            val key = url.substringAfter("/v1/sessions/")
            val v = slots[key] ?: return HttpResponse(404, ByteArray(0))
            return HttpResponse(200, v)
        }
        override fun sleep(millis: Long) = Thread.sleep(millis)
    }

    private fun softwareDevice(seedByte: Int): DeviceIdentity {
        val seed = ByteArray(32) { (it + seedByte).toByte() }
        val enc = DeviceIdentity.generateEncryptionKey()
        return DeviceIdentity(
            signPublicKey = Ed25519Group.publicKeyFromSeed(seed),
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            signFn = { msg -> Ed25519Engine.sign(seed, msg) },
        )
    }

    private val relayBase = "http://relay.test"
    private val now = 1_724_700_000L

    /** Run both sides' handshakes concurrently and return (initiator SAS, responder handshake). */
    private fun pair(
        auth: DeviceAuthorization,
        invitation: DeviceAuthorization.Invitation,
        pairing: DevicePairing,
    ): Pair<String, DevicePairing.Handshake> {
        var sasInitiator = ""
        var responderHandshake: DevicePairing.Handshake? = null
        var responderError: Throwable? = null
        val tA = Thread { runCatching { sasInitiator = auth.handshake(invitation) } }
        val tB =
            Thread {
                runCatching { responderHandshake = pairing.begin(invitation.inviteQr) }.onFailure {
                    responderError =
                        it
                }
            }
        tA.start()
        tB.start()
        tA.join(15_000)
        tB.join(15_000)
        responderError?.let { throw it }
        return sasInitiator to responderHandshake!!
    }

    @Test
    fun genesisAuthorisesTheFirstDeviceWithAGenesisAdd() {
        val http = RelayTransport()
        val user = UserIdentity.create()
        val newDevice = softwareDevice(seedByte = 11)

        val auth = DeviceAuthorization(http, user, clock = { now }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, newDevice, clock = { now }, pollIntervalMillis = 10)

        val salt = ByteArray(32) { (it * 5 + 1).toByte() }
        val invitation = auth.invite(relayBase, salt)
        assertTrue(invitation.inviteQr.startsWith("voidbind:pair?"), "must be a pairing invite")
        assertTrue(invitation.inviteQr.contains("v=3"), "invite must carry version 3")
        assertTrue(invitation.inviteQr.contains("usr=ed25519%3A"), "invite must carry the identity")
        assertEquals(user.userId.render(), invitation.userId)

        val (sasInitiator, handshake) = pair(auth, invitation, pairing)
        assertEquals(sasInitiator, handshake.sas, "both screens must show the same SAS")
        assertEquals(Pairing.DIGITS, handshake.sas.length)
        assertEquals(user.userId.render(), handshake.userId)

        val ops = auth.authorise(invitation)
        val admission = pairing.confirm(handshake)

        val op = MembershipOp.verify(admission.op)
        assertTrue(op.genesis, "the first add is signed by genesis")
        assertEquals(emptyList(), op.prev)
        assertEquals(KeyRef.ed25519(newDevice.signPublicKey).render(), op.device)
        assertEquals(KeyRef.x25519(newDevice.encPublicKey).render(), op.deviceEnc)
        assertEquals(ops, admission.ops, "initiator and responder hold the same replica")
        val view = Membership.evaluate(user.userId.render(), admission.ops, now)
        assertTrue(view.isMember(op.device))
    }

    @Test
    fun aMemberDeviceAdmitsTheNextDeviceWithNoSecretAnywhere() {
        val http = RelayTransport()
        val user = UserIdentity.create()
        val usr = user.userId.render()

        // Phone A was admitted by genesis (a v2 self-enrolment cert — the installed
        // base, which IS a genesis add). It holds no user key from here on.
        val phoneA = softwareDevice(seedByte = 21)
        val certA = Enrolment.selfEnrol(user, phoneA, issuedAt = now - 60, lifetimeSeconds = 3600)
        val phoneB = softwareDevice(seedByte = 31)

        val auth =
            DeviceAuthorization(http, phoneA, admittingOp = certA, knownOps = emptyList(), clock = {
                now
            }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, phoneB, clock = { now }, pollIntervalMillis = 10)

        val invitation = auth.invite(relayBase)
        assertEquals(usr, invitation.userId, "the invite names the identity, not the phone")

        val (sasInitiator, handshake) = pair(auth, invitation, pairing)
        assertEquals(sasInitiator, handshake.sas)

        val opsA = auth.authorise(invitation)
        val admission = pairing.confirm(handshake)

        val op = MembershipOp.verify(admission.op)
        assertTrue(!op.genesis)
        assertEquals(KeyRef.ed25519(phoneA.signPublicKey).render(), op.by, "the add is signed by phone A")
        assertEquals(listOf(MembershipOp.hash(certA)), op.prev, "…citing A's own admission as its head")
        assertEquals(KeyRef.ed25519(phoneB.signPublicKey).render(), op.device)
        assertEquals(2, admission.ops.size)
        assertEquals(opsA, admission.ops)

        val view = Membership.evaluate(usr, admission.ops, now)
        assertTrue(view.isMember(KeyRef.ed25519(phoneA.signPublicKey).render()))
        assertTrue(view.isMember(KeyRef.ed25519(phoneB.signPublicKey).render()))
        assertEquals(listOf(op.hash), view.heads)

        // And B, now a member with no secret either, can admit C.
        val phoneC = softwareDevice(seedByte = 41)
        val authB =
            DeviceAuthorization(http, phoneB, admission.op, admission.ops, clock = { now + 1 }, pollIntervalMillis = 10)
        val pairingC = DevicePairing(http, phoneC, clock = { now + 1 }, pollIntervalMillis = 10)
        val invC = authB.invite(relayBase)
        val (sasB, hsC) = pair(authB, invC, pairingC)
        assertEquals(sasB, hsC.sas)
        authB.authorise(invC)
        val admC = pairingC.confirm(hsC)
        val viewC = Membership.evaluate(usr, admC.ops, now + 1)
        assertEquals(3, viewC.members.size)
    }

    @Test
    fun aNonMemberInitiatorGetsNoSas() {
        val http = RelayTransport()
        val user = UserIdentity.create()
        val stranger = UserIdentity.create()
        val phoneA = softwareDevice(seedByte = 51)
        // A's admitting op is signed by a DIFFERENT identity's genesis.
        val foreignCert = Enrolment.selfEnrol(stranger, phoneA, issuedAt = now - 60, lifetimeSeconds = 3600)

        // The initiator refuses itself at invite time (its ops do not make it a member of…
        // well, they do — of the stranger's identity). So it CAN invite, naming the stranger.
        val auth = DeviceAuthorization(http, phoneA, foreignCert, emptyList(), clock = { now }, pollIntervalMillis = 10)
        val invitation = auth.invite(relayBase)
        assertEquals(stranger.userId.render(), invitation.userId)

        // But a responder that (via the QR) expects USER's identity evaluates A's ops
        // under `user` and finds no member → no SAS, a PROTOCOL failure, nothing signed.
        val forged = invitation.inviteQr.replace(
            "usr=" + stranger.userId.render().replace(":", "%3A"),
            "usr=" + user.userId.render().replace(":", "%3A"),
        )
        val phoneB = softwareDevice(seedByte = 61)
        val pairing = DevicePairing(http, phoneB, clock = { now }, pollIntervalMillis = 10)
        var initiatorOutcome: PairingOutcome<String>? = null
        var responderOutcome: PairingOutcome<DevicePairing.Handshake>? = null
        val tA = Thread { initiatorOutcome = auth.handshakeCatching(invitation) }
        val tB = Thread { responderOutcome = pairing.beginCatching(forged) }
        tA.start()
        tB.start()
        tA.join(15_000)
        tB.join(15_000)
        val failed = assertIs<PairingOutcome.Failed>(responderOutcome)
        assertEquals(PairingFailureKind.PROTOCOL, failed.kind)
        // The initiator side completed its handshake (it cannot know), but nothing was authorised.
        assertIs<PairingOutcome.Ready<String>>(initiatorOutcome)
    }

    @Test
    fun aDeviceWhoseOpsDoNotMakeItAMemberCannotInvite() {
        val http = RelayTransport()
        val user = UserIdentity.create()
        val phoneA = softwareDevice(seedByte = 71)
        val expired = Enrolment.selfEnrol(user, phoneA, issuedAt = now - 7200, lifetimeSeconds = 3600)
        val auth = DeviceAuthorization(http, phoneA, expired, emptyList(), clock = { now }, pollIntervalMillis = 10)
        assertFailsWith<IllegalStateException> { auth.invite(relayBase) }
        val failed = assertIs<PairingOutcome.Failed>(auth.inviteCatching(relayBase))
        assertEquals(PairingFailureKind.PROTOCOL, failed.kind)
    }
}
