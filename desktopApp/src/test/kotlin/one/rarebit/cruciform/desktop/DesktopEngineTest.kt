package one.rarebit.cruciform.desktop

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.DeviceKeyStore
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.approval.Approval
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.custody.GoDeviceDir
import one.rarebit.voidwhichbinds.flow.DevicePairing
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The desktop engine over void-which-binds-go's `device-dir` vector: a real sealed device
 * directory, enrolled, with a second member. Network calls go to a recording fake.
 */
class DesktopEngineTest {

    private val v: Map<String, Any> by lazy {
        val raw = javaClass.getResourceAsStream("/vectors/device-dir/sealed-enrolled.json")
            ?.readBytes()?.decodeToString() ?: error("vectors/device-dir/sealed-enrolled.json missing")
        MiniJson.parseObject(raw)
    }

    @Suppress("UNCHECKED_CAST")
    private fun obj(m: Any?): Map<String, Any> = m as Map<String, Any>

    private val now: Long by lazy { Instant.parse(v["now"] as String).epochSecond }
    private val self: String by lazy { obj(v["device"])["public_key"] as String }

    @Suppress("UNCHECKED_CAST")
    private val other: String by lazy { (v["members"] as List<String>).single { it != self } }

    private val tmp = mutableListOf<Path>()

    @AfterTest
    fun cleanUp() {
        tmp.forEach { it.toFile().deleteRecursively() }
    }

    /** Records every request and answers from [answer] (404 by default). */
    private class FakeHttp(
        val answer: (String, ByteArray?) -> HttpResponse = { _, _ -> HttpResponse(404, ByteArray(0)) },
    ) : HttpTransport {
        val posts = mutableListOf<Pair<String, String>>()

        override fun get(url: String) = answer(url, null)

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            posts += url to body?.decodeToString().orEmpty()
            return answer(url, body)
        }

        override fun put(url: String, body: ByteArray, contentType: String?) = answer(url, body)

        override fun sleep(millis: Long) = Unit
    }

    private fun engine(http: HttpTransport, settings: DesktopSettings = DesktopSettings()): DesktopEngine {
        val dir = Files.createTempDirectory("desktop-device").also(tmp::add)
        for ((name, body) in obj(v["files"])) {
            val bytes = if (name ==
                v["sealed_file_name"]
            ) {
                Hex.decode(body as String)
            } else {
                (body as String).encodeToByteArray()
            }
            Files.write(dir.resolve(name), bytes)
        }
        val store = DesktopSettings.Store(
            Files.createTempDirectory("desktop-settings").also(tmp::add).resolve("s.json"),
        )
        store.save(settings)
        return DesktopEngine(GoDeviceDir(dir) { now }, store, http, { now })
    }

    private fun unlock(e: DesktopEngine) = e.unlock((v["passphrase"] as String).encodeToByteArray())

    @Test
    fun theOverviewIsGosDirectoryAndAsksNothing() {
        val e = engine(FakeHttp())
        val o = e.overview()
        assertEquals(obj(v["device"])["name"], o.name)
        assertEquals(self, o.deviceId)
        assertEquals(v["enrolled_user"], o.userId)
        assertTrue(o.userFingerprint!!.isNotBlank())
        assertEquals(listOf(self, other), o.members.map { it.id })
        assertTrue(o.members[0].isThisDevice)
        assertEquals("this device", o.members[1].admittedBy)
        assertFalse(o.unlocked)
    }

    @Test
    fun removingADeviceSignsARemoveOnceUnlockedAndTellsTheSites() {
        val http = FakeHttp { _, _ -> HttpResponse(200, ByteArray(0)) }
        val e = engine(http, DesktopSettings(membershipRps = listOf("https://rp.example/")))
        assertFailsWith<IllegalArgumentException> { e.removeDevice(self) }
        assertFailsWith<DesktopEngine.LockedException> { e.removeDevice(other) }
        assertEquals(2, e.dir.ops().size) // nothing was written while locked
        unlock(e)
        e.removeDevice(other)
        val ops = e.dir.ops()
        val remove = ops.map { MembershipOp.verify(it) }.single { it.kind == MembershipOp.Kind.REMOVE }
        assertEquals(other, remove.device)
        assertEquals(self, remove.by)
        assertFalse(Membership.evaluate(v["enrolled_user"] as String, ops, now).isMember(other))
        val (url, body) = http.posts.single()
        assertEquals("https://rp.example/membership/${v["enrolled_user"]}", url)
        assertTrue(ops.all { body.contains(it) })
        e.lock()
        assertFalse(e.isUnlocked)
    }

    @Test
    fun aRemoveShortOfQuorumIsRefusedAndNothingIsRecorded() {
        val e = engine(FakeHttp())
        // A third member raises the fleet high-water to 3: a remove then needs two signatures.
        val keys = e.dir.keys({ (v["passphrase"] as String).encodeToByteArray() })
        val third = DeviceKeyStore.getOrCreate("desktop-engine-test-third").publicKey().render()
        val enc = KeyRef.x25519(DeviceIdentity.generateEncryptionKey().publicKey).render()
        val user = v["enrolled_user"] as String
        val add = MembershipOp.sign(
            keys.deviceIdentity().asSigner(),
            keys.signPublicKey,
            user,
            MembershipOp.Kind.ADD,
            dev = third,
            deviceEnc = enc,
            prev = e.dir.membership().heads,
            issuedAt = now,
        )
        e.dir.recordOps(listOf(add))
        assertEquals(3, e.overview().members.size)
        unlock(e)
        val before = e.dir.ops()
        val err = assertFailsWith<IllegalStateException> { e.removeDevice(other) }
        assertTrue(err.message!!.contains("two members' signatures"))
        assertEquals(before, e.dir.ops())
        assertTrue(Membership.evaluate(user, before, now).isMember(other))
    }

    @Suppress("ThrowsCount") // each case throws what a step would
    @Test
    fun aSigningPairingStepLetsLockedThroughToTheUnlockDialog() {
        val e = engine(FakeHttp())
        assertFailsWith<DesktopEngine.LockedException> {
            e.signingStep("https://relay.example") { throw DesktopEngine.LockedException() }
        }
        assertFailsWith<DesktopEngine.LockedException> {
            e.signingStep("https://relay.example") {
                throw java.io.IOException("wrapped", DesktopEngine.LockedException())
            }
        }
        val other = assertFailsWith<IllegalStateException> {
            e.signingStep("https://relay.example") { throw java.net.ConnectException("refused") }
        }
        assertTrue(other !is DesktopEngine.LockedException)
        assertTrue(other.message!!.isNotBlank())
    }

    /**
     * A faithful in-memory relay: opaque, write-once slots. With [loseCertReply] the first
     * admission write is stored but answered 500 (the reply lost on the way back); with
     * [rejectFirstCert] it is refused and not stored.
     */
    private class Relay(val loseCertReply: Boolean = false, val rejectFirstCert: Boolean = false) : HttpTransport {
        private var certPuts = 0

        private val slots = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()
        private var seq = 0

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            if (url.endsWith(
                    "/v1/sessions",
                )
            ) {
                return HttpResponse(200, """{"session_id":"s${++seq}"}""".encodeToByteArray())
            }
            return HttpResponse(404, ByteArray(0))
        }

        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse {
            val key = url.substringAfter("/v1/sessions/")
            val cert = key.endsWith("/cert")
            if (cert) certPuts++
            val first = cert && certPuts == 1
            val status = when {
                first && rejectFirstCert -> 503

                // refused, not stored
                slots.putIfAbsent(key, body) != null -> 409

                first && loseCertReply -> 500

                // stored, the reply lost
                else -> 204
            }
            return HttpResponse(status, ByteArray(0))
        }

        override fun get(url: String): HttpResponse =
            slots[url.substringAfter("/v1/sessions/")]?.let { HttpResponse(200, it) } ?: HttpResponse(404, ByteArray(0))

        override fun sleep(millis: Long) = Thread.sleep(millis)
    }

    private fun newDevice(alias: String): DeviceIdentity {
        val ks = DeviceKeyStore.getOrCreate(alias)
        val enc = DeviceIdentity.generateEncryptionKey()
        return DeviceIdentity(ks.publicKey().bytes, enc.publicKey, enc.privateKey) { ks.sign(it) }
    }

    private class Paired(
        val engine: DesktopEngine,
        val invite: DesktopEngine.Invite,
        val pairing: DevicePairing,
        val handshake: DevicePairing.Handshake,
        val device: DeviceIdentity,
    )

    /** This desktop invites; a new device joins over [relay]; both reach the same code. */
    private fun pairUpToTheCode(relay: Relay, alias: String): Paired {
        val e = engine(relay, DesktopSettings(relay = "http://relay.test"))
        unlock(e)
        val invite = e.startAddDevice()
        val device = newDevice(alias)
        val pairing = DevicePairing(relay, device, { now }, pollIntervalMillis = 10)
        var handshake: DevicePairing.Handshake? = null
        val joiner = Thread { handshake = pairing.begin(invite.qr) }.apply { start() }
        val code = e.awaitSecurityCode(invite)
        joiner.join(15_000)
        assertEquals(DesktopEngine.formatSas(handshake!!.sas), code)
        return Paired(e, invite, pairing, handshake!!, device)
    }

    @Test
    fun addingADeviceAdmitsItAndRecordsTheAdd() {
        val p = pairUpToTheCode(Relay(), "desktop-engine-test-new-a")
        p.engine.authorise(p.invite)
        val admission = p.pairing.confirm(p.handshake)
        val newId = KeyRef.ed25519(p.device.signPublicKey).render()
        val add = MembershipOp.verify(admission.op)
        assertEquals(newId, add.device)
        assertEquals(self, add.by) // signed by this desktop's sealed key
        assertTrue(p.engine.dir.ops().contains(admission.op))
        assertEquals(listOf(self, other, newId), p.engine.overview().members.map { it.id })
    }

    /** The first delivery fails; the retry delivers the same add, and the new device confirms. */
    private fun retryAfterAFailedDelivery(p: Paired) {
        val before = p.engine.dir.ops()
        assertFailsWith<IllegalStateException> { p.engine.authorise(p.invite) }
        assertEquals(before, p.engine.dir.ops()) // nothing recorded before delivery is confirmed
        p.engine.authorise(p.invite)
        val admission = p.pairing.confirm(p.handshake)
        val newId = KeyRef.ed25519(p.device.signPublicKey).render()
        val adds = p.engine.dir.ops().map { MembershipOp.verify(it) }.filter { it.device == newId }
        assertEquals(listOf(admission.op), adds.map { it.token }) // the one add, signed once
    }

    @Test
    fun aRefusedDeliveryIsRetriedWithTheSameAdd() =
        retryAfterAFailedDelivery(pairUpToTheCode(Relay(rejectFirstCert = true), "desktop-engine-test-new-b"))

    @Test
    fun aLostDeliveryReplyIsRecognisedOnRetry() =
        retryAfterAFailedDelivery(pairUpToTheCode(Relay(loseCertReply = true), "desktop-engine-test-new-d"))

    @Test
    fun aFailedRecordingIsRetriedWithoutSigningAgain() {
        val p = pairUpToTheCode(Relay(), "desktop-engine-test-new-c")
        val ops = p.engine.dir.opsPath
        // The replica can't be written: the delivery succeeds, the recording fails.
        Files.delete(ops)
        Files.createDirectory(ops)
        assertFailsWith<java.io.IOException> { p.engine.authorise(p.invite) }
        val admission = p.pairing.confirm(p.handshake) // the new device was admitted
        Files.delete(ops)
        p.engine.authorise(p.invite) // records the same signed add, signs nothing new
        assertTrue(p.engine.dir.ops().contains(admission.op))
        assertEquals(
            1,
            p.engine.dir.ops().count {
                MembershipOp.verify(it).device ==
                    admission.let { a -> MembershipOp.verify(a.op).device }
            },
        )
        val recorded = p.engine.dir.ops()
        p.engine.authorise(p.invite) // idempotent from here on
        assertEquals(recorded, p.engine.dir.ops())
    }

    @Test
    fun addingADeviceNeedsARelay() {
        val e = engine(FakeHttp())
        val err = assertFailsWith<IllegalStateException> { e.startAddDevice() }
        assertTrue(err.message!!.contains("relay"))
    }

    @Test
    fun fetchingAnApprovalProvesPossessionToEachBrokerInTurn() {
        val nonce = Base64Url.encode(ByteArray(32) { (it + 1).toByte() })
        val handle = Base64Url.encode(ByteArray(32) { (it + 101).toByte() })
        val http = FakeHttp { url, _ ->
            when {
                url.endsWith("/approval/fetch-nonce") -> HttpResponse(200, """{"nonce":"$nonce"}""".encodeToByteArray())
                else -> HttpResponse(Approval.FETCH_REFUSAL_STATUS, Approval.FETCH_REFUSAL_BODY.encodeToByteArray())
            }
        }
        val e = engine(http, DesktopSettings(brokers = listOf("https://a.example/broker", "https://b.example:8443")))
        unlock(e)
        val err = assertFailsWith<IllegalStateException> { e.fetchApproval("void-which-binds:approve?h=$handle\n") }
        assertTrue(err.message!!.contains("https://a.example refused it; https://b.example:8443 refused it"))
        val fetches = http.posts.filter { it.first.endsWith("/approval/fetch") }
        assertEquals(
            listOf("https://a.example/broker/approval/fetch", "https://b.example:8443/approval/fetch"),
            fetches.map {
                it.first
            },
        )
        val body = MiniJson.parseObject(fetches[0].second)
        assertEquals(handle, body["handle"])
        assertEquals(nonce, body["nonce"])
        val cert = obj(v["files"])[GoDeviceDir.CERT_FILE].toString().trim()
        assertTrue((body["credential"] as String).startsWith("$cert~"))
    }

    @Test
    fun anUnreachableBrokerIsSkippedForTheNext() {
        val nonce = Base64Url.encode(ByteArray(32) { (it + 1).toByte() })
        val handle = Base64Url.encode(ByteArray(32) { (it + 101).toByte() })
        val http = FakeHttp { url, _ ->
            when {
                url.startsWith("https://down.example") -> throw java.net.ConnectException("refused")
                url.endsWith("/approval/fetch-nonce") -> HttpResponse(200, """{"nonce":"$nonce"}""".encodeToByteArray())
                else -> HttpResponse(Approval.FETCH_REFUSAL_STATUS, Approval.FETCH_REFUSAL_BODY.encodeToByteArray())
            }
        }
        val e = engine(http, DesktopSettings(brokers = listOf("https://down.example", "https://up.example")))
        unlock(e)
        val err = assertFailsWith<IllegalStateException> { e.fetchApproval("void-which-binds:approve?h=$handle") }
        assertTrue(err.message!!.contains("https://down.example could not be reached"))
        assertTrue(http.posts.any { it.first == "https://up.example/approval/fetch" })
    }

    @Test
    fun anApprovalLinkMustBeOne() {
        val e = engine(FakeHttp(), DesktopSettings(brokers = listOf("https://a.example")))
        assertFailsWith<Approval.ApprovalException> { e.fetchApproval("void-which-binds:login?rp=x") }
    }

    @Test
    fun settingsRoundTrip() {
        val e = engine(FakeHttp())
        val s = DesktopSettings("https://relay.example", listOf("https://rp.example"), listOf("https://broker.example"))
        e.saveSettings(s)
        assertEquals(s, e.settings)
    }

    @Test
    fun aBrokersAudienceIsItsOrigin() {
        assertEquals("https://b.example:8443", DesktopEngine.originOf("https://b.example:8443/x/y"))
        assertEquals("https://a.example", DesktopEngine.originOf(" https://a.example/broker "))
        assertFailsWith<IllegalArgumentException> { DesktopEngine.originOf("a.example") }
        assertEquals("123 4567", DesktopEngine.formatSas("1234567"))
    }
}
