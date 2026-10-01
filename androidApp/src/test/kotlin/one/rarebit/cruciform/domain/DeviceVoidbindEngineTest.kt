package one.rarebit.cruciform.domain

import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.platform.StrongAuth
import one.rarebit.cruciform.testing.FakeBiometric
import one.rarebit.cruciform.testing.FakeTransport
import one.rarebit.cruciform.testing.InMemoryPrefs
import one.rarebit.cruciform.testing.InMemorySealer
import one.rarebit.cruciform.testing.SoftwareDeviceKeys
import one.rarebit.voidwhichbinds.AuthenticationRequiredException
import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.Invite
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * [DeviceVoidbindEngine] end to end over its seams: a software Ed25519 device key in
 * place of StrongBox, in-memory prefs/sealer in place of SharedPreferences/AndroidKeyStore,
 * a scripted HTTP transport and biometric. What stays real is everything the engine
 * itself decides — provisioning, the replica, the membership evaluation, the failure
 * classification — plus the library's actual crypto.
 *
 * Hardware non-extractability and the real biometric gate are device-tested
 * (docs/DEVICE-TESTING.md); nothing here claims otherwise.
 */
class DeviceVoidbindEngineTest {

    private val store = IdentityStore(InMemoryPrefs(), InMemorySealer())
    private val policyStore = ApprovalPolicyStore(InMemoryPrefs())
    private val transport = FakeTransport()
    private val biometric = FakeBiometric()
    private val keys = SoftwareDeviceKeys(HardwareBacking.TEE)
    private var relay = RELAY
    private var notify = ""
    private var now = NOW

    private fun engine(membershipRps: List<String> = emptyList()) = DeviceVoidbindEngine(
        store = store,
        policyStore = policyStore,
        transport = transport,
        biometric = biometric,
        relay = { relay },
        notify = { notify },
        clock = { now },
        membershipRps = membershipRps,
        deviceKeys = keys,
        defaultDeviceName = { "Test Phone" },
    )

    private val selfId: String get() = KeyRef.ed25519(keys.publicKey).render()

    /** A second member, admitted by genesis (the recovery secret) — as a Restore would admit it. */
    private fun admitSibling(rawSecret: String): String {
        val user = UserIdentity.restore(rawSecret)
        val sibling = SoftwareDeviceKeys().getOrCreate()
        val enc = DeviceIdentity.generateEncryptionKey()
        val device = DeviceIdentity(sibling.publicKey, enc.publicKey, enc.privateKey) { sibling.sign(it) }
        store.recordOps(listOf(Enrolment.selfEnrol(user, device, NOW)))
        return KeyRef.ed25519(sibling.publicKey).render()
    }

    // --- identity lifecycle ------------------------------------------------------

    @Test
    fun `refresh with nothing provisioned is None`() = runTest {
        val engine = engine()
        assertEquals(IdentityState.Loading, engine.identity.value)

        assertEquals(EngineResult.Ready(Unit), engine.refresh())

        assertEquals(IdentityState.None, engine.identity.value)
    }

    @Test
    fun `createIdentity provisions an owner and publishes Active`() = runTest {
        val engine = engine()

        val backup = ready(engine.createIdentity())

        val user = UserIdentity.restore(backup.rawSecret)
        assertEquals(backup.rawSecret.chunked(4).joinToString(" "), backup.groupedSecret)
        val state = active(engine)
        assertEquals("Test Phone", state.identity.label)
        assertEquals(user.userId.render(), state.identity.fullKey)
        assertEquals(HardwareBacking.TEE, state.device.backing) // the key's REAL tier, not assumed
        assertTrue(state.device.label.startsWith("dev · "))
        assertTrue(store.hasUserKey())
        assertTrue(state.holdsRecoverySecret)
        assertTrue(backup.keptOnDevice)
        assertEquals(1, store.knownOps().size)
    }

    @Test
    fun `without a strong biometric the phone keeps no copy, but the identity is still created`() = runTest {
        for (outcome in listOf(StrongAuth.CANCELLED, StrongAuth.UNAVAILABLE)) {
            val store = IdentityStore(InMemoryPrefs(), InMemorySealer())
            biometric.strong = outcome
            val engine = DeviceVoidbindEngine(
                store = store,
                policyStore = policyStore,
                transport = transport,
                biometric = biometric,
                relay = { relay },
                clock = { now },
                membershipRps = emptyList(),
                deviceKeys = SoftwareDeviceKeys(),
                defaultDeviceName = { "Test Phone" },
            )

            val backup = ready(engine.createIdentity())

            assertFalse(backup.keptOnDevice)
            assertTrue(store.isProvisioned())
            assertFalse(store.hasUserKey())
            assertFalse(active(engine).holdsRecoverySecret)
        }
    }

    @Test
    fun `restoreIdentity re-derives the same user identity from the secret`() = runTest {
        val backup = ready(engine().createIdentity())
        val createdKey = active(engine().apply { refresh() }).identity.fullKey

        val otherStore = IdentityStore(InMemoryPrefs(), InMemorySealer())
        val restored = DeviceVoidbindEngine(
            store = otherStore,
            policyStore = ApprovalPolicyStore(InMemoryPrefs()),
            transport = transport,
            biometric = biometric,
            relay = { relay },
            clock = { NOW },
            membershipRps = emptyList(),
            deviceKeys = SoftwareDeviceKeys(),
            defaultDeviceName = { "Second Phone" },
        )
        assertEquals(EngineResult.Ready(Unit), restored.restoreIdentity(backup.rawSecret))

        assertEquals(createdKey, active(restored).identity.fullKey)
        assertTrue(otherStore.hasUserKey())
    }

    @Test
    fun `restoreIdentity with a mistyped secret fails with the parser's reason and provisions nothing`() = runTest {
        val f = failure(engine().restoreIdentity("void-which-binds1notarealsecret"))

        assertEquals(EngineFailure.Kind.INTERNAL, f.kind)
        assertFalse(f.retryable)
        // The parser's own explanation (a bad checksum / length) — not the generic fallback.
        assertNotEquals("That recovery secret could not be read.", f.message)
        assertFalse(store.isProvisioned())
    }

    @Test
    fun `a lapsed key window prompts once and retries`() = runTest {
        keys.authRequiredLoads = 1

        engine().createIdentity()

        assertEquals(listOf("Authenticate", "Keep a recovery copy on this phone"), biometric.prompts)
        assertTrue(store.isProvisioned())
    }

    @Test
    fun `a lapsed key window with the prompt declined is CANCELLED and provisions nothing`() = runTest {
        keys.authRequiredLoads = 1
        biometric.presence = false

        val f = failure(engine().createIdentity())

        assertEquals(EngineFailure("Authentication cancelled.", EngineFailure.Kind.CANCELLED, retryable = false), f)
        assertFalse(store.isProvisioned())
    }

    @Test
    fun `an unexpected keystore error is a Failed with a human message, never raw text`() = runTest {
        val engine = DeviceVoidbindEngine(
            store = store,
            policyStore = policyStore,
            transport = transport,
            biometric = biometric,
            relay = { relay },
            clock = { NOW },
            membershipRps = emptyList(),
            deviceKeys = { throw java.security.KeyStoreException("HAL error 0x1d") },
            defaultDeviceName = { "Test Phone" },
        )

        val f = failure(engine.createIdentity())

        assertEquals("Couldn't create the identity.", f.message)
        assertEquals(EngineFailure.Kind.INTERNAL, f.kind)
    }

    @Test
    fun `a cancellation is never turned into a Failed`() = runTest {
        val engine = engine()
        val sibling = admitSibling(ready(engine.createIdentity()).rawSecret)
        biometric.cancelWith = CancellationException("screen left")

        // The coroutine is being torn down: the engine must rethrow, not report a failure
        // for a dead caller to render.
        assertFailsWith<CancellationException> { engine.revealRecoverySecret() }
        // …including through the pairing boundary, which used to catch Throwable.
        assertFailsWith<CancellationException> { engine.removeDevice(sibling) }
    }

    @Test
    fun `revealRecoverySecret needs a strong biometric and returns the kept secret`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())
        biometric.prompts.clear()

        assertEquals(EngineResult.Ready(backup), engine.revealRecoverySecret())
        assertEquals(listOf("Show recovery secret"), biometric.prompts)

        biometric.strong = StrongAuth.CANCELLED
        assertEquals(EngineFailure.Kind.CANCELLED, failure(engine.revealRecoverySecret()).kind)
    }

    @Test
    fun `the screen-lock PIN never reveals the recovery secret`() = runTest {
        val engine = engine()
        ready(engine.createIdentity())
        // A PIN satisfies the ordinary presence check, but this device has no strong
        // biometric: the genesis secret stays sealed.
        biometric.presence = true
        biometric.strong = StrongAuth.UNAVAILABLE

        val f = failure(engine.revealRecoverySecret())

        assertEquals(EngineFailure.Kind.NOT_YET, f.kind) // a refusal with a way forward, not a cancel
        assertTrue(f.message.contains("PIN can't authorise it"))
    }

    @Test
    fun `revealRecoverySecret refuses on a device that keeps no secret`() = runTest {
        val f = failure(engine().revealRecoverySecret())

        assertEquals("This device keeps no copy of the recovery secret.", f.message)
        assertEquals(EngineFailure.Kind.NOT_YET, f.kind)
        assertTrue(biometric.prompts.isEmpty())
    }

    // --- the written backup (void-which-binds-go ADR-0010) --------------------------------

    @Test
    fun `a created identity asks for its backup to be confirmed, a restored one does not`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())
        assertTrue(active(engine).backup.confirmPending)
        assertEquals(null, active(engine).backup.lastCheckedLabel)
        // The identity's fingerprint is the printable one, as on paper and the CLI.
        assertTrue(Regex("[A-Z2-7]{4}( [A-Z2-7]{4}){3}").matches(active(engine).identity.fingerprint))

        val otherStore = IdentityStore(InMemoryPrefs(), InMemorySealer())
        val restored = DeviceVoidbindEngine(
            store = otherStore,
            policyStore = ApprovalPolicyStore(InMemoryPrefs()),
            transport = transport,
            biometric = biometric,
            relay = { relay },
            clock = { now },
            membershipRps = emptyList(),
            deviceKeys = SoftwareDeviceKeys(),
            defaultDeviceName = { "Second Phone" },
        )
        ready(restored.restoreIdentity(backup.groupedSecret))
        assertFalse(active(restored).backup.confirmPending)
        assertTrue(active(restored).backup.lastCheckedLabel!!.startsWith("Checked "))
    }

    @Test
    fun `verifying the written secret records the check and signs nothing`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())
        val opsBefore = store.knownOps()
        biometric.prompts.clear()

        val check = ready(engine.verifyRecoverySecret(backup.groupedSecret.uppercase()))

        assertEquals(active(engine).identity.fingerprint, check.fingerprint)
        assertFalse(active(engine).backup.confirmPending)
        assertEquals(opsBefore, store.knownOps())
        assertTrue(biometric.prompts.isEmpty()) // knowing the secret is the proof
    }

    @Test
    fun `another identity's secret, or a typo, is refused`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())

        val other = failure(engine.verifyRecoverySecret(UserIdentity.create().recovery.format()))
        assertTrue(other.message.startsWith("That secret belongs to a different identity"))

        val raw = backup.rawSecret
        val typo = raw.dropLast(1) + (if (raw.last() == 'q') 'p' else 'q')
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.verifyRecoverySecret(typo)).kind)
        assertTrue(active(engine).backup.confirmPending)
    }

    @Test
    fun `the phone's copy can be removed only after a check, and only with a strong biometric`() = runTest {
        val engine = engine()
        val backup = ready(engine.createIdentity())

        val tooEarly = failure(engine.forgetRecoverySecret())
        assertTrue(tooEarly.message.startsWith("Check your written recovery secret first"))
        assertEquals(EngineFailure.Kind.NOT_YET, tooEarly.kind) // "Not yet", not "Something went wrong"
        assertTrue(store.hasUserKey())

        ready(engine.verifyRecoverySecret(backup.rawSecret))
        biometric.strong = StrongAuth.UNAVAILABLE
        assertTrue(failure(engine.forgetRecoverySecret()).message.contains("PIN can't authorise it"))
        assertTrue(store.hasUserKey())

        biometric.strong = StrongAuth.SUCCESS
        assertEquals(EngineResult.Ready(Unit), engine.forgetRecoverySecret())
        assertFalse(store.hasUserKey())
        assertFalse(active(engine).holdsRecoverySecret)
        // The device is still a member and can still check the paper.
        assertFalse(active(engine).membership.lapsed)
        ready(engine.verifyRecoverySecret(backup.rawSecret))
    }

    // --- renewal (membership, ADR-0005) --------------------------------------------

    @Test
    fun `a fresh device is not due for renewal`() = runTest {
        val engine = engine()
        ready(engine.createIdentity())

        val health = active(engine).membership
        assertFalse(health.renewalDue)
        assertFalse(health.lapsed)
        assertTrue(health.renewsByLabel!!.startsWith("renews by "))
    }

    @Test
    fun `inside the window the device renews itself and presents the new add`() = runTest {
        val engine = engine()
        ready(engine.createIdentity())
        val firstCredential = store.load()!!.enrolmentCert

        now = NOW + 70 * DAY // 20 days before the 90-day add lapses
        engine.refresh()
        assertTrue(active(engine).membership.renewalDue)

        assertEquals(EngineResult.Ready(Unit), engine.renewMembership())

        val renewed = store.load()!!
        assertNotEquals(firstCredential, renewed.enrolmentCert)
        assertEquals(2, renewed.ops.size) // the old add stays as history
        assertFalse(active(engine).membership.renewalDue)

        // Past the FIRST add's expiry, the device is still a member.
        now = NOW + 100 * DAY
        engine.refresh()
        assertFalse(active(engine).membership.lapsed)
    }

    @Test
    fun `a lapsed device cannot renew itself`() = runTest {
        val engine = engine()
        ready(engine.createIdentity())

        now = NOW + 100 * DAY
        engine.refresh()
        assertTrue(active(engine).membership.lapsed)

        val f = failure(engine.renewMembership())

        assertTrue(f.message.startsWith("This device is no longer a member"))
        assertEquals(EngineFailure.Kind.NOT_YET, f.kind)
        assertEquals(1, store.knownOps().size)
    }

    @Test
    fun `parseScanned never throws on junk`() {
        assertEquals(ScannedCode.Unknown("not a code"), engine().parseScanned("not a code"))
    }

    @Test
    fun `parseScanned reads a recovery sheet's secret in either case, or grouped`() {
        val raw = UserIdentity.create().recovery.format()
        val engine = engine()

        for (scanned in listOf(raw, raw.uppercase(), raw.chunked(4).joinToString(" "))) {
            assertEquals(ScannedCode.RecoverySecret(scanned), engine.parseScanned(scanned))
        }
    }

    @Test
    fun `parseScanned refuses a secret with a broken checksum`() {
        val raw = UserIdentity.create().recovery.format()
        val last = raw.last()
        val typo = raw.dropLast(1) + (if (last == 'q') 'p' else 'q')

        assertEquals(ScannedCode.Unknown(typo.uppercase()), engine().parseScanned(typo.uppercase()))
    }

    @Test
    fun `login and pairing codes keep precedence over the recovery-secret reading`() {
        val engine = engine()
        val login = LoginQr.encode(RP, "L1")
        val usr = UserIdentity.create().userId.render()
        val invite = Invite.encode(RELAY, "sess1", ByteArray(32) { it.toByte() }, usr)

        assertIs<ScannedCode.WebLogin>(engine.parseScanned(login))
        assertIs<ScannedCode.PairInvite>(engine.parseScanned(invite))
    }

    @Test
    fun `a scanned secret never prints itself`() {
        val raw = UserIdentity.create().recovery.format()

        assertFalse(ScannedCode.RecoverySecret(raw).toString().contains(raw))
    }

    @Test
    fun `the backup carries the fingerprint and user id the sheet prints`() = runTest {
        val backup = ready(engine().createIdentity())

        val user = UserIdentity.restore(backup.rawSecret)
        assertEquals(user.fingerprint, backup.fingerprint)
        assertEquals(user.userId.render(), backup.userId)
    }

    // --- web login -----------------------------------------------------------------

    private val login = ScannedCode.WebLogin(RP, "L1", "voidbind:login?…")

    private fun challengeJson(): String {
        val nonce = Base64Url.encode(ByteArray(32) { 1 })
        return """{"id":"L1","nonce":"$nonce","audience":"$RP","expires_at":${NOW + 60}}"""
    }

    private fun rpServes(approveStatus: Int = 204) {
        transport.handler = { method, url, _ ->
            when {
                method == "GET" && url == "$RP/login/L1/challenge" ->
                    HttpResponse(200, challengeJson().encodeToByteArray())

                method == "POST" && url == "$RP/login/L1/approve" -> HttpResponse(approveStatus, ByteArray(0))

                else -> HttpResponse(404, ByteArray(0))
            }
        }
    }

    @Test
    fun `fetchLoginRequest without an identity fails cleanly`() = runTest {
        val f = failure(engine().fetchLoginRequest(login))

        assertEquals(EngineFailure("No identity on this device.", EngineFailure.Kind.INTERNAL, retryable = false), f)
        assertTrue(transport.requests.isEmpty())
    }

    @Test
    fun `fetchLoginRequest maps an unreachable RP to UNREACHABLE, not a throw`() = runTest {
        val engine = engine()
        engine.createIdentity()

        val f = failure(engine.fetchLoginRequest(login))

        assertEquals(EngineFailure.Kind.UNREACHABLE, f.kind)
        assertEquals("Couldn't reach the site.", f.message)
    }

    @Test
    fun `fetchLoginRequest maps a 404 challenge to EXPIRED and a 500 to REJECTED`() = runTest {
        val engine = engine()
        engine.createIdentity()
        transport.handler = { _, _, _ -> HttpResponse(404, ByteArray(0)) }

        val expired = failure(engine.fetchLoginRequest(login))
        assertEquals(EngineFailure.Kind.EXPIRED, expired.kind)
        assertFalse(expired.retryable)

        transport.handler = { _, _, _ -> HttpResponse(500, ByteArray(0)) }
        assertEquals(EngineFailure.Kind.REJECTED, failure(engine.fetchLoginRequest(login)).kind)
    }

    @Test
    fun `approving with nothing fetched is a Failed, not a throw`() = runTest {
        val engine = engine()
        engine.createIdentity()

        val f = failure(engine.approveLogin(login))

        // The precondition ("no login in progress") is library-internal: the human sees
        // the one sign-in message.
        assertEquals("Couldn't complete the sign-in.", f.message)
        assertEquals("Couldn't complete the sign-in.", failure(engine.approveNumberMatch(login, 42)).message)
    }

    @Test
    fun `approving a fetched login signs, trusts the site and records the approval`() = runTest {
        val engine = engine()
        engine.createIdentity()
        rpServes()

        val request = ready(engine.fetchLoginRequest(login))
        assertEquals("rp.example.test", request.domain)
        assertEquals(60, request.expiresInSeconds)
        assertTrue(request.candidates.isEmpty())

        assertEquals(EngineResult.Ready(Unit), engine.approveLogin(login))

        assertTrue(transport.requests.contains("POST $RP/login/L1/approve"))
        assertEquals(listOf("rp.example.test"), active(engine).trustedSites.map { it.id })
        val activity = ready(engine.approvalActivity())
        assertEquals(1, activity.size)
        assertTrue(activity.single().approved)
        assertEquals("just now", activity.single().whenLabel)
        // The pending login is consumed.
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.approveLogin(login)).kind)
    }

    @Test
    fun `an RP refusing the approval is a Failed that leaks no HTTP detail and trusts nothing`() = runTest {
        val engine = engine()
        engine.createIdentity()
        rpServes(approveStatus = 403)
        engine.fetchLoginRequest(login)

        val f = failure(engine.approveLogin(login))

        assertEquals("Couldn't complete the sign-in.", f.message)
        assertFalse(f.message.contains("403"))
        assertTrue(active(engine).trustedSites.isEmpty())
        assertTrue(ready(engine.approvalActivity()).isEmpty())
    }

    @Test
    fun `a declined prompt on approval is CANCELLED`() = runTest {
        engine().createIdentity()
        biometric.prompts.clear()
        rpServes()
        biometric.presence = false
        // The next signature finds the key's auth window lapsed.
        val lapsing = DeviceVoidbindEngine(
            store = store,
            policyStore = policyStore,
            transport = transport,
            biometric = biometric,
            relay = { relay },
            clock = { NOW },
            membershipRps = emptyList(),
            deviceKeys = {
                object : DeviceSigningKey {
                    override val publicKey: ByteArray get() = keys.publicKey
                    override fun sign(message: ByteArray): ByteArray = throw AuthenticationRequiredException("lapsed")
                    override fun backing(): HardwareBacking = HardwareBacking.TEE
                }
            },
            defaultDeviceName = { "Test Phone" },
        )
        ready(lapsing.fetchLoginRequest(login))

        val f = failure(lapsing.approveLogin(login))

        assertEquals(EngineFailure.Kind.CANCELLED, f.kind)
        assertEquals(listOf("Authenticate"), biometric.prompts)
    }

    @Test
    fun `denying a fetched login records a denial and signs nothing`() = runTest {
        val engine = engine()
        engine.createIdentity()
        rpServes()
        engine.fetchLoginRequest(login)

        assertEquals(EngineResult.Ready(Unit), engine.denyLogin())

        assertFalse(transport.requests.any { it.startsWith("POST") })
        assertFalse(ready(engine.approvalActivity()).single().approved)
        assertTrue(active(engine).trustedSites.isEmpty())
    }

    @Test
    fun `denyLogin with nothing pending is a no-op`() = runTest {
        val engine = engine()
        assertEquals(EngineResult.Ready(Unit), engine.denyLogin())
        assertTrue(ready(engine.approvalActivity()).isEmpty())
    }

    // --- push ------------------------------------------------------------------------

    @Test
    fun `registerForPush fails without an identity or a configured plane, without dialling`() = runTest {
        val engine = engine()
        notify = NOTIFY
        assertEquals("No identity on this device.", failure(engine.registerForPush(ENDPOINT)).message)

        engine.createIdentity()
        notify = ""
        assertEquals("No push plane is set up.", failure(engine.registerForPush(ENDPOINT)).message)
        assertTrue(transport.requests.isEmpty())
    }

    @Test
    fun `registerForPush turns a transport failure into a Failed`() = runTest {
        val engine = engine()
        engine.createIdentity()
        notify = NOTIFY

        val f = failure(engine.registerForPush(ENDPOINT))

        assertEquals("Couldn't register this device for sign-in wake-ups.", f.message)
        assertEquals(1, transport.requests.size)
        // Best-effort teardown too: a failure is a value, never a throw.
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.unregisterFromPush()).kind)
    }

    @Test
    fun `registerForPush does not leak the plane's refusal text`() = runTest {
        val engine = engine()
        engine.createIdentity()
        notify = NOTIFY
        transport.handler = { _, _, _ -> HttpResponse(403, ByteArray(0)) }

        assertFalse(failure(engine.registerForPush(ENDPOINT)).message.contains("403"))
    }

    @Test
    fun `registerForPush succeeds when the plane accepts`() = runTest {
        val engine = engine()
        engine.createIdentity()
        notify = NOTIFY
        transport.handler = { _, _, _ ->
            val body = """{"user_id":"u","device_key":"d","channel":"ntfy","expires_at":1}"""
            HttpResponse(200, body.encodeToByteArray())
        }

        assertEquals(EngineResult.Ready(Unit), engine.registerForPush(ENDPOINT))
        assertTrue(transport.requests.single().startsWith("POST $NOTIFY"))
    }

    @Test
    fun `unregisterFromPush with nothing to unregister succeeds quietly`() = runTest {
        assertEquals(EngineResult.Ready(Unit), engine().unregisterFromPush())
        assertTrue(transport.requests.isEmpty())
    }

    // --- pairing: every failure is a value, never a throw ----------------------------

    @Test
    fun `startPairInvite with no relay configured says so without dialling`() = runTest {
        val engine = engine()
        engine.createIdentity()
        relay = ""

        val f = failure(engine.startPairInvite())

        assertEquals(EngineFailure.Kind.REJECTED, f.kind)
        assertFalse(f.retryable)
        assertTrue(transport.requests.isEmpty())
    }

    @Test
    fun `startPairInvite without an identity is an internal failure`() = runTest {
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine().startPairInvite()).kind)
    }

    @Test
    fun `startPairInvite against an unreachable relay is retryable UNREACHABLE naming the host`() = runTest {
        val engine = engine()
        engine.createIdentity()

        val f = failure(engine.startPairInvite())

        assertEquals(EngineFailure.Kind.UNREACHABLE, f.kind)
        assertTrue(f.retryable)
        assertTrue(f.message, f.message.contains("relay.example.test"))
    }

    @Test
    fun `awaitPairHandshake and confirmPairing with nothing in progress are internal failures`() = runTest {
        val engine = engine()
        engine.createIdentity()

        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.awaitPairHandshake()).kind)
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.confirmPairing()).kind)
    }

    @Test
    fun `joinPairInvite with a malformed invite is a non-retryable protocol failure`() = runTest {
        val f = failure(engine().joinPairInvite(ScannedCode.PairInvite(RELAY, "s1", "voidbind:pair?garbage")))

        assertEquals(EngineFailure.Kind.PROTOCOL, f.kind)
        assertFalse(f.retryable)
    }

    // --- devices (membership) ----------------------------------------------------

    @Test
    fun `devices lists this device first, admitted by genesis`() = runTest {
        val engine = engine()
        assertEquals(EngineResult.Ready(emptyList<MemberDevice>()), engine.devices())
        val backup = ready(engine.createIdentity())
        val sibling = admitSibling(backup.rawSecret)

        val devices = ready(engine.devices())

        assertEquals(listOf(selfId, sibling), devices.map { it.id })
        assertTrue(devices.first().isThisDevice)
        assertFalse(devices.last().isThisDevice)
        assertEquals("genesis (recovery key)", devices.first().admittedByLabel)
    }

    @Test
    fun `removeDevice refuses this device, a non-member and a missing identity`() = runTest {
        val engine = engine()
        assertEquals(EngineFailure.Kind.INTERNAL, failure(engine.removeDevice(selfId)).kind)

        engine.createIdentity()
        biometric.prompts.clear()
        assertTrue(failure(engine.removeDevice(selfId)).message.contains("can't remove itself"))
        assertTrue(failure(engine.removeDevice("ed25519:" + "00".repeat(32))).message.contains("not a member"))
        assertTrue(biometric.prompts.isEmpty()) // refused before any prompt
    }

    @Test
    fun `removeDevice needs a strong biometric`() = runTest {
        val engine = engine()
        val sibling = admitSibling(ready(engine.createIdentity()).rawSecret)

        biometric.strong = StrongAuth.CANCELLED
        assertEquals(EngineFailure.Kind.CANCELLED, failure(engine.removeDevice(sibling)).kind)

        biometric.strong = StrongAuth.UNAVAILABLE
        val f = failure(engine.removeDevice(sibling))
        assertFalse(f.retryable)
        assertTrue(f.message.contains("fingerprint or face"))

        assertEquals(2, ready(engine.devices()).size) // nothing was signed
    }

    @Test
    fun `removeDevice signs a remove, drops the member and pushes the replica to each RP`() = runTest {
        val engine = engine(membershipRps = listOf("$RP/", "https://down.example.test"))
        val sibling = admitSibling(ready(engine.createIdentity()).rawSecret)
        val usr = active(engine).identity.fullKey
        transport.handler = { _, url, _ ->
            if (url.startsWith(RP)) HttpResponse(200, ByteArray(0)) else throw java.io.IOException("down")
        }

        assertEquals(EngineResult.Ready(Unit), engine.removeDevice(sibling))

        assertEquals(listOf(selfId), ready(engine.devices()).map { it.id })
        assertEquals(3, store.knownOps().size) // genesis add, sibling add, the remove
        assertEquals(
            listOf("POST $RP/membership/$usr", "POST https://down.example.test/membership/$usr"),
            transport.requests,
        )
    }

    // --- settings + policy -------------------------------------------------------

    @Test
    fun `settings changes are persisted and republished`() = runTest {
        val engine = engine()
        engine.createIdentity()

        assertEquals(EngineResult.Ready(Unit), engine.renameDevice("Work phone"))
        assertEquals(EngineResult.Ready(Unit), engine.setBiometricApproval(false))

        val state = active(engine)
        assertEquals("Work phone", state.device.name)
        assertEquals("Work phone", state.identity.label)
        assertFalse(state.biometricApproval)
    }

    @Test
    fun `site policy toggles between trusted and pinned always-ask, and revoke forgets it`() = runTest {
        val engine = engine()
        engine.createIdentity()
        assertEquals(
            SitePolicyView("a.example", ApprovalPolicy.AlwaysAsk, pinnedAlwaysAsk = false),
            ready(engine.sitePolicy("a.example")),
        )

        engine.setAlwaysAsk("a.example", alwaysAsk = false)
        assertTrue(ready(engine.sitePolicy("a.example")).trusted)

        engine.setAlwaysAsk("a.example", alwaysAsk = true)
        assertTrue(ready(engine.sitePolicy("a.example")).pinnedAlwaysAsk)
        assertFalse(ready(engine.sitePolicy("a.example")).trusted)

        store.upsertTrustedSite(TrustedSite("a.example", "a.example", "", "just now"))
        engine.refresh()
        assertTrue(active(engine).trustedSites.single().pinnedAlwaysAsk) // policy joined onto the row

        engine.revokeSite("a.example")
        assertTrue(active(engine).trustedSites.isEmpty())
        assertFalse(ready(engine.sitePolicy("a.example")).pinnedAlwaysAsk)
    }

    private companion object {
        const val NOW = 1_800_000_000L
        const val DAY = 24L * 60 * 60
        const val RELAY = "https://relay.example.test/pair"
        const val NOTIFY = "https://notify.example.test"
        const val RP = "https://rp.example.test"
        const val ENDPOINT = "https://push.example.test/up/abc"
    }
}
