package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.GoCheckout
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.JdkHttpTransport
import one.rarebit.voidwhichbinds.net.WebLoginClient
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * CROSS-LANGUAGE proof for the app-facing COORDINATORS (not just the raw clients):
 * the whole [UserIdentity] → [Enrolment] → [LoginApproval] / [DeviceAuthorization]
 * + [DevicePairing] stack driven against a LIVE void-which-binds-go (v0.9.0, ADR-0007).
 * Skipped (not failed) when `go`/the void-which-binds-go checkout is absent, so CI stays green.
 *
 *  - login: a coordinator-driven device approves a login on the real Go RP, which
 *    verifies the kmp-derived identity's self-enrolled cert + assertion.
 *  - pairing (genesis): the two coordinators authorise a first device THROUGH the
 *    real Go relay.
 *  - pairing (phone → phone): a MEMBER phone, holding no secret, admits the next
 *    phone through the real Go relay; the new phone then logs in on the real Go RP
 *    presenting the ops — Go's `rp.Verifier` evaluates the KMP-minted v3 add (signed
 *    by the phone, citing its heads) and mints a token. Without the ops the same
 *    credential is refused (the RP cannot judge an admission whose past it has not
 *    seen) — the `Voidbind-Membership` / `ops` mechanism, proven end to end.
 *  - pairing (phone → Go): the real Go CLI (`void-which-binds pair-join`) joins a KMP member
 *    phone's invite and records the admission in its device store.
 */
class CoordinatorGoInteropTest {
    private val goDir = GoCheckout.dir
    private fun goAvailable(): Boolean = goDir.isDirectory && System.getenv("PATH").orEmpty().split(File.pathSeparator)
        .any { File(it, "go").canExecute() }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun buildCli(): File {
        val out = File.createTempFile("vb-coord-interop", "").apply { delete() }
        val p = ProcessBuilder("go", "build", "-o", out.absolutePath, GoCheckout.cliPackage)
            .directory(goDir).redirectErrorStream(true).start()
        val log = p.inputStream.readBytes().decodeToString()
        assertEquals(0, p.waitFor(), "go build failed: $log")
        return out
    }

    private fun waitReady(within: Long = 20_000, check: () -> Boolean) {
        val http = JdkHttpTransport()
        val deadline = System.currentTimeMillis() + within
        while (System.currentTimeMillis() < deadline) {
            try {
                if (check()) return
            } catch (_: Exception) {}
            http.sleep(100)
        }
        throw IllegalStateException("server not ready within ${within}ms")
    }

    private fun softwareDevice(user: UserIdentity, seedByte: Int, now: Long): Pair<DeviceIdentity, String> {
        val seed = ByteArray(32) { (it + seedByte).toByte() }
        val enc = DeviceIdentity.generateEncryptionKey()
        val device = DeviceIdentity(
            signPublicKey = Ed25519Group.publicKeyFromSeed(seed),
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            signFn = { msg -> Ed25519Engine.sign(seed, msg) },
        )
        val cert = Enrolment.selfEnrol(user, device, issuedAt = now, lifetimeSeconds = 3600)
        return device to cert
    }

    /** Both handshakes concurrently: (initiator SAS, responder handshake). */
    private fun pair(
        auth: DeviceAuthorization,
        invitation: DeviceAuthorization.Invitation,
        pairing: DevicePairing,
    ): Pair<String, DevicePairing.Handshake> {
        var sasInitiator = ""
        var handshake: DevicePairing.Handshake? = null
        var err: Throwable? = null
        val tA = Thread { runCatching { sasInitiator = auth.handshake(invitation) }.onFailure { err = it } }
        val tB = Thread { runCatching { handshake = pairing.begin(invitation.inviteQr) }.onFailure { err = it } }
        tA.start()
        tB.start()
        tA.join(20_000)
        tB.join(20_000)
        err?.let { throw it }
        return sasInitiator to handshake!!
    }

    @Test
    fun loginApprovalApprovesOnLiveGoRpForARecoveryDerivedIdentity() {
        assumeTrue(goAvailable(), "voidbind-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val port = freePort()
        val base = "http://127.0.0.1:$port"

        // A kmp recovery-derived identity the Go RP pins.
        val user = UserIdentity.create()
        val now = System.currentTimeMillis() / 1000
        val (device, cert) = softwareDevice(user, seedByte = 13, now = now)

        val proc = ProcessBuilder(
            cli.absolutePath,
            "login-serve",
            "--addr",
            "127.0.0.1:$port",
            "--pin",
            user.userId.render(),
        )
            .redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$base/login").status == 200 }

            // Browser side opens a login → a real voidbind:login QR.
            val created = WebLoginClient(http, base).createLogin()

            // The device approves it through the coordinator.
            val flow = LoginApproval(http, device, cert)
            val request = flow.begin(created.qr)
            flow.approve(request)

            val poll = WebLoginClient(http, base).poll(created.id)
            assertEquals("approved", poll.status, "the Go RP must approve the coordinator's assertion")
            assertTrue(!poll.token.isNullOrEmpty(), "the Go RP must mint a token")
            assertEquals(user.userId.render(), poll.user, "principal must be the recovery-derived kmp identity")
        } finally {
            proc.destroyForcibly()
        }
    }

    @Test
    fun coordinatorsPairANewDeviceThroughTheLiveGoRelay() {
        assumeTrue(goAvailable(), "voidbind-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val port = freePort()
        val base = "http://127.0.0.1:$port"

        val proc = ProcessBuilder(cli.absolutePath, "relay", "--addr", "127.0.0.1:$port")
            .redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$base/v1/sessions").status == 200 }

            val user = UserIdentity.create()
            val now = System.currentTimeMillis() / 1000
            val (newDevice, _) = softwareDevice(user, seedByte = 17, now = now)

            val auth = DeviceAuthorization(http, user, clock = { now }, pollIntervalMillis = 20)
            val pairing = DevicePairing(http, newDevice, clock = { now }, pollIntervalMillis = 20)

            val invitation = auth.invite(base)
            val (sasInitiator, hs) = pair(auth, invitation, pairing)
            assertEquals(sasInitiator, hs.sas, "SAS must match through the live Go relay")
            assertEquals(Pairing.DIGITS, hs.sas.length)

            auth.authorise(invitation)
            val admission = pairing.confirm(hs)

            val op = MembershipOp.verify(admission.op)
            assertTrue(op.genesis)
            assertEquals(user.userId.render(), op.user)
            assertEquals(KeyRef.ed25519(newDevice.signPublicKey).render(), op.device)
        } finally {
            proc.destroyForcibly()
        }
    }

    @Test
    fun memberPhoneAdmitsTheNextPhoneThroughTheLiveGoRelayAndTheGoRpHonoursTheOps() {
        assumeTrue(goAvailable(), "voidbind-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val relayPort = freePort()
        val relayBase = "http://127.0.0.1:$relayPort"
        val rpPort = freePort()
        val rpBase = "http://127.0.0.1:$rpPort"

        val user = UserIdentity.create()
        val usr = user.userId.render()
        val now = System.currentTimeMillis() / 1000
        // Phone A: admitted by genesis (its self-enrolled v2 cert IS a genesis add). From
        // here on the user key is never used — A admits B with its own device key.
        val (phoneA, certA) = softwareDevice(user, seedByte = 23, now = now - 60)
        val (phoneB, _) = softwareDevice(user, seedByte = 29, now = now)

        val relay = ProcessBuilder(
            cli.absolutePath,
            "relay",
            "--addr",
            "127.0.0.1:$relayPort",
        ).redirectErrorStream(true).start()
        val rp = ProcessBuilder(
            cli.absolutePath,
            "login-serve",
            "--addr",
            "127.0.0.1:$rpPort",
            "--pin",
            usr,
        ).redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$relayBase/v1/sessions").status == 200 }
            waitReady { http.post("$rpBase/login").status == 200 }

            // --- phone → phone through the Go relay ---------------------------------
            val auth =
                DeviceAuthorization(http, phoneA, admittingOp = certA, knownOps = emptyList(), clock = {
                    now
                }, pollIntervalMillis = 20)
            val pairing = DevicePairing(http, phoneB, clock = { now }, pollIntervalMillis = 20)
            val invitation = auth.invite(relayBase)
            assertEquals(usr, invitation.userId)
            val (sasA, hsB) = pair(auth, invitation, pairing)
            assertEquals(sasA, hsB.sas, "SAS must match through the live Go relay")
            val opsA = auth.authorise(invitation)
            val admission = pairing.confirm(hsB)
            val opB = MembershipOp.verify(admission.op)
            assertEquals(KeyRef.ed25519(phoneA.signPublicKey).render(), opB.by, "B's add is signed by phone A")
            assertEquals(listOf(MembershipOp.hash(certA)), opB.prev)
            assertEquals(opsA, admission.ops)
            assertTrue(
                Membership.evaluate(usr, admission.ops, now).isMember(KeyRef.ed25519(phoneB.signPublicKey).render()),
            )

            // --- the Go RP, which pinned only the genesis key, must honour B ---------
            val web = WebLoginClient(http, rpBase)

            // Without the ops the RP has no way to judge B's admission (bad_prev: A's
            // add is a past it has never seen) → refused. This is the negative half of
            // the proof that the presented ops are what makes B a member there.
            val bare = web.createLogin()
            val bareFlow = LoginApproval(http, phoneB, admission.op)
            assertFailsWith<IllegalArgumentException> { bareFlow.approve(bareFlow.begin(bare.qr)) }
            assertEquals("pending", web.poll(bare.id).status, "an admission with no past is not a member on Go")

            // With the ops (the `ops` field of the assertion) Go evaluates A's genesis
            // add + A's add of B and authenticates B as `usr`.
            val created = web.createLogin()
            val flow = LoginApproval(http, phoneB, admission.op, knownOps = admission.ops)
            flow.approve(flow.begin(created.qr))
            val poll = web.poll(created.id)
            assertEquals("approved", poll.status, "the Go RP must evaluate the KMP-minted member add")
            assertTrue(!poll.token.isNullOrEmpty())
            assertEquals(usr, poll.user, "B authenticates as the identity, admitted by a phone Go never met")

            // And the RP recorded the ops: B's bare credential now works on its own.
            val again = web.createLogin()
            val bareAgain = LoginApproval(http, phoneB, admission.op)
            bareAgain.approve(bareAgain.begin(again.qr))
            assertEquals("approved", web.poll(again.id).status, "the RP's op log makes the admission durable")
        } finally {
            relay.destroyForcibly()
            rp.destroyForcibly()
        }
    }

    @Test
    fun theGoCliJoinsAKmpMemberPhonesInvite() {
        assumeTrue(goAvailable(), "voidbind-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val relayPort = freePort()
        val relayBase = "http://127.0.0.1:$relayPort"

        val user = UserIdentity.create()
        val usr = user.userId.render()
        val now = System.currentTimeMillis() / 1000
        val (phoneA, certA) = softwareDevice(user, seedByte = 37, now = now - 60)
        val goStore = Files.createTempDirectory("vb-go-device").toFile()

        val relay = ProcessBuilder(
            cli.absolutePath,
            "relay",
            "--addr",
            "127.0.0.1:$relayPort",
        ).redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$relayBase/v1/sessions").status == 200 }

            val auth = DeviceAuthorization(http, phoneA, certA, emptyList(), clock = { now }, pollIntervalMillis = 20)
            val invitation = auth.invite(relayBase)

            // The real Go CLI is the new device: it evaluates the phone's revealed ops
            // under the invite's usr, derives the SAS, "confirms" (--yes), receives the
            // sealed admission and enrols its device store.
            val join = ProcessBuilder(
                cli.absolutePath, "pair-join", "--invite", invitation.inviteQr,
                "--device-dir", goStore.absolutePath, "--name", "go-mac", "--yes",
            ).redirectErrorStream(true).start()
            val sas = auth.handshake(invitation)
            val ops = auth.authorise(invitation)
            val out = join.inputStream.readBytes().decodeToString()
            assertEquals(0, join.waitFor(), "pair-join must succeed: $out")
            assertTrue(out.contains("admitted into $usr"), "Go must report the admission: $out")
            assertTrue(out.contains("2 membership ops recorded"), "Go must hold A's add + the new add: $out")
            assertTrue(out.contains(sas.substring(0, 3)), "Go must have shown the same SAS: $out")
            assertEquals(2, ops.size)

            // The Go device store now holds the KMP-signed add (ops.jsonl) and can be
            // evaluated as a member of the phone's identity.
            val replica = File(goStore, "ops.jsonl").readLines().filter { it.isNotBlank() }
            assertEquals(2, replica.size)
            val view = Membership.evaluate(usr, replica, now)
            assertEquals(2, view.members.size, "phone A and the Go device are the members")
            assertTrue(view.isMember(KeyRef.ed25519(phoneA.signPublicKey).render()))
        } finally {
            relay.destroyForcibly()
            goStore.deleteRecursively()
        }
    }
}
