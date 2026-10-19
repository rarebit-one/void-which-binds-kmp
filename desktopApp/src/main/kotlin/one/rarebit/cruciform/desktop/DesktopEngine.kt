package one.rarebit.cruciform.desktop

import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.UserFingerprint
import one.rarebit.voidwhichbinds.WebLogin
import one.rarebit.voidwhichbinds.approval.Approval
import one.rarebit.voidwhichbinds.approval.FetchRequest
import one.rarebit.voidwhichbinds.approval.Handle
import one.rarebit.voidwhichbinds.approval.OpenedApproval
import one.rarebit.voidwhichbinds.auth.DeviceCredential
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.custody.GoDeviceDir
import one.rarebit.voidwhichbinds.custody.SealedDeviceKeys
import one.rarebit.voidwhichbinds.flow.DeviceAuthorization
import one.rarebit.voidwhichbinds.flow.LoginApproval
import one.rarebit.voidwhichbinds.flow.PairingFailures
import one.rarebit.voidwhichbinds.flow.PairingOutcome
import one.rarebit.voidwhichbinds.net.ApprovalClient
import one.rarebit.voidwhichbinds.net.ApprovalFetchRefusedException
import one.rarebit.voidwhichbinds.net.ApprovalHttpException
import one.rarebit.voidwhichbinds.net.HttpTransport
import java.io.IOException
import java.net.URI
import java.time.Instant

/**
 * The desktop authenticator's brain, with no UI in it: this machine's sealed device in
 * void-which-binds-go's device directory ([GoDeviceDir]), its keys ([SealedDeviceKeys]), and
 * the library flows driven over them. Every method blocks (files, the KDF, the network); the
 * UI calls them off its thread.
 *
 * The keys never ask for the passphrase themselves: a private operation on locked keys
 * throws [LockedException], and the UI asks with its own dialog and calls [unlock]. So a
 * dismissed prompt can never be the "failed first unlock" that [SealedDeviceKeys] keeps.
 */
@Suppress("TooManyFunctions") // the app's one facade over the library: a method per UI action
class DesktopEngine(
    val dir: GoDeviceDir,
    private val settingsStore: DesktopSettings.Store,
    private val http: HttpTransport,
    private val clock: () -> Long = { Instant.now().epochSecond },
    private val ttlMillis: Long = SealedDeviceKeys.DEFAULT_TTL_MILLIS,
) : AutoCloseable {
    /** A private operation needs the passphrase: unlock, then try again. */
    class LockedException : IllegalStateException("This device is locked. Unlock it with its passphrase.")

    /** This device as the overview shows it. */
    class Overview(
        val name: String,
        /** `ed25519:<hex>`. */
        val deviceId: String,
        /** The user this device signs in as (`ed25519:<hex>`), when enrolled. */
        val userId: String?,
        /** The printable user fingerprint, when enrolled. */
        val userFingerprint: String?,
        val members: List<Member>,
        val unlocked: Boolean,
    ) {
        val enrolled: Boolean get() = userId != null
    }

    class Member(
        val id: String,
        val short: String,
        val isThisDevice: Boolean,
        val admittedBy: String,
        val admittedAt: Long,
        val expiresAt: Long,
    )

    /** A minted "Add a device" invite: the QR the new device scans. */
    class Invite internal constructor(
        val qr: String,
        val session: String,
        internal val authorization: DeviceAuthorization,
        internal val invitation: DeviceAuthorization.Invitation,
        internal val relay: String,
    )

    @Volatile var settings: DesktopSettings = settingsStore.load()
        private set

    private var keys: SealedDeviceKeys? = null

    private fun keys(): SealedDeviceKeys = synchronized(this) {
        keys ?: dir.keys({ throw LockedException() }, ttlMillis).also { keys = it }
    }

    val isUnlocked: Boolean get() = synchronized(this) { keys?.isUnlocked == true }

    /** Unlocks with [passphrase] (zeroed after use). Throws `SealedFileException.OpenFailed` if wrong. */
    fun unlock(passphrase: ByteArray) = keys().unlock(passphrase)

    /** Drops the held seeds now. */
    fun lock() {
        synchronized(this) { keys?.close() }
    }

    override fun close() = lock()

    fun saveSettings(s: DesktopSettings) {
        settingsStore.save(s)
        settings = s
    }

    /** Reads the device directory now. Asks nothing. */
    fun overview(): Overview {
        val dev = dir.load()
        val self = dev.record.publicKey
        val user = dev.enrolledUser
        val members = if (user == null) emptyList() else members(dir.membership(), self)
        return Overview(
            name = dev.record.name,
            deviceId = self,
            userId = user,
            userFingerprint = user?.let { UserFingerprint.of(KeyRef.parse(it).bytes) },
            members = members,
            unlocked = isUnlocked,
        )
    }

    private fun members(view: Membership.View, self: String): List<Member> = view.members.values
        .sortedWith(compareBy<Membership.Member> { it.device != self }.thenBy { it.admittedAt })
        .map { m ->
            val admitting = view.accepted[m.admittedBy]
            Member(
                id = m.device,
                short = shortKey(m.device),
                isThisDevice = m.device == self,
                admittedBy = when {
                    admitting == null -> "unknown"
                    admitting.genesis -> "the recovery key"
                    admitting.by == self -> "this device"
                    else -> shortKey(admitting.by)
                },
                admittedAt = m.admittedAt,
                expiresAt = m.expiresAt,
            )
        }

    // --- Add a device (this device is the initiator) ---------------------------------

    /** Mints an invite through the configured relay. Signs nothing yet. */
    fun startAddDevice(): Invite {
        val relay = settings.relay.ifBlank { error("No pairing relay is set up. Add one in Settings.") }
        val (cert, ops) = enrolment()
        val authorization = DeviceAuthorization(
            http,
            keys().deviceIdentity(),
            cert,
            ops,
            clock,
            maxWaitMillis = INVITE_WAIT_MILLIS,
        )
        val inv = outcome(authorization.inviteCatching(relay))
        return Invite(inv.inviteQr, inv.relaySession, authorization, inv, relay)
    }

    /** Waits (polls the relay) for the new device, then returns the security code to compare. */
    fun awaitSecurityCode(invite: Invite): String =
        formatSas(outcome(invite.authorization.handshakeCatching(invite.invitation)))

    /**
     * After the person has matched the codes: signs the new device's add with this device's
     * key, delivers it, and records the ops in the replica. Throws [LockedException] if the
     * hold has lapsed; unlock and call it again.
     */
    fun authorise(invite: Invite) {
        // Retry-safe in the library: the add is signed once, and a retry after a failed
        // delivery re-sends that same admission. So the add is recorded only once delivery
        // is confirmed, and a failure leaves the invite ready for "It matches" again.
        val ops = signingStep(invite.relay) { invite.authorization.authorise(invite.invitation) }
        dir.recordOps(ops)
        pushMembership()
    }

    /** The codes did not match: tells the new device, signed, so it stops waiting. */
    fun refuse(invite: Invite) {
        signingStep(invite.relay) { invite.authorization.refuse(invite.invitation) }
    }

    /**
     * A pairing step that signs: locked keys surface as [LockedException], so the app can
     * unlock and run it again. (The library's `*Catching` steps would classify that as a
     * protocol failure.) Any other failure is classified against [relay] as they would be.
     */
    @Suppress("TooGenericExceptionCaught") // the library's own catching steps catch everything too
    internal fun <T> signingStep(relay: String, step: () -> T): T = try {
        step()
    } catch (e: Exception) {
        generateSequence<Throwable>(e) { it.cause }.filterIsInstance<LockedException>().firstOrNull()?.let { throw it }
        error(PairingFailures.classify(e, relay).message)
    }

    // --- Devices ---------------------------------------------------------------------

    /**
     * Signs a `remove` of [deviceId] with this device's key, citing the replica's heads,
     * records it, and tells the configured relying parties.
     */
    fun removeDevice(deviceId: String) {
        val dev = dir.load()
        val self = dev.record.publicKey
        require(deviceId != self) { "This device can't remove itself. Remove it from another device." }
        val user = dev.enrolledUser ?: error("This device isn't enrolled, so it can't remove devices.")
        val now = clock()
        val view = dir.membership()
        check(view.isMember(self)) { "This device is no longer a member, so it can't remove others." }
        require(view.isMember(deviceId)) { "That device isn't a member any more." }
        val k = keys()
        val op = MembershipOp.sign(
            k.asEd25519Signer(),
            k.signPublicKey,
            user,
            MembershipOp.Kind.REMOVE,
            dev = deviceId,
            deviceEnc = "",
            prev = view.heads,
            issuedAt = now,
        )
        // Evaluate before recording: a remove short of quorum (rule 5: two distinct members'
        // signatures once the fleet has had three or more devices) would be recorded as an
        // ineffective `under_threshold` op and change nothing, so nothing is written for it.
        val after = Membership.evaluate(user, Membership.merge(dir.ops(), listOf(dev.enrolmentCert!!), listOf(op)), now)
        if (after.isMember(deviceId)) {
            val why = after.ineffective[MembershipOp.hash(op)]
            check(why != Membership.Reason.UNDER_THRESHOLD) {
                "Removing a device needs two members' signatures once this identity has had three or more " +
                    "devices, and this desktop can't collect the second. Nothing was recorded."
            }
            error("The removal would not take effect${why?.let { " ($it)" }.orEmpty()}. Nothing was recorded.")
        }
        dir.recordOps(listOf(op))
        pushMembership()
    }

    // --- Web login -------------------------------------------------------------------

    /** Fetches the sign-in a `void-which-binds:login?…` link names. Signs nothing. */
    fun beginLogin(link: String): Pair<LoginApproval, LoginApproval.Request> {
        val (cert, ops) = enrolment()
        val approval = LoginApproval(http, keys().deviceIdentity(), cert, knownOps = ops)
        return when (val o = approval.beginCatching(link.trim())) {
            is LoginApproval.Outcome.Ready -> approval to o.request
            is LoginApproval.Outcome.Failed -> error(o.message)
        }
    }

    /** Signs and submits the sign-in; [chosen] is the number tapped for a number-matching one. */
    fun approveLogin(approval: LoginApproval, request: LoginApproval.Request, chosen: Int?) {
        if (chosen == null) approval.approve(request) else approval.approve(request, chosen)
    }

    // --- Action approvals (ADR-0019) -------------------------------------------------

    /**
     * Fetches the approval a `void-which-binds:approve?h=…` link names from each configured
     * broker in turn, proving this device's possession for that broker's audience. Returns
     * the opened challenge and action, with its digest recomputed. Answering one is not
     * possible from here yet: no broker serves a submit endpoint (its host routes them).
     */
    fun fetchApproval(link: String): Pair<String, OpenedApproval> {
        val handle = Approval.parseApprove(link.trim())
        val brokers = settings.brokers.ifEmpty { error("No approval broker is set up. Add one in Settings.") }
        val (cert, ops) = enrolment()
        val failures = mutableListOf<String>()
        for (broker in brokers) {
            try {
                return broker to fetchFrom(broker, handle, cert, ops)
            } catch (_: ApprovalFetchRefusedException) {
                failures += "${originOf(broker)} refused it"
            } catch (e: LockedException) {
                throw e
            } catch (e: IOException) {
                failures += "${originOf(broker)} could not be reached (${e.message})"
            } catch (e: ApprovalHttpException) {
                failures += "${originOf(broker)} answered HTTP ${e.status}"
            }
        }
        error(
            "No broker would show this approval: ${failures.joinToString("; ")}. " +
                "It may have expired or been answered.",
        )
    }

    /** One broker's authenticated fetch (ADR-0019): a nonce, the possession proof, the fetch. */
    private fun fetchFrom(broker: String, handle: Handle, cert: String, ops: List<String>): OpenedApproval {
        val k = keys()
        val audience = originOf(broker)
        val client = ApprovalClient(http, broker, audience)
        val nonce = client.fetchNonce()
        val signer = k.asEd25519Signer()
        val proof = Approval.signFetchProofWith(signer, k.signPublicKey, audience, handle, nonce)
        val credential = DeviceCredential.mint(cert, signer, clock()).value
        return client.fetch(FetchRequest(handle, nonce, credential, WebLogin.presentable(ops), emptyList(), proof))
    }

    // --- internals -------------------------------------------------------------------

    /** The admitting op and the replica, or a plain refusal for an unenrolled device. */
    private fun enrolment(): Pair<String, List<String>> {
        val dev = dir.load()
        val cert = dev.enrolmentCert ?: error("This device isn't enrolled with an identity.")
        return cert to Membership.merge(dir.ops(), listOf(cert))
    }

    /** Best effort: tells each configured relying party the replica now. Returns how many accepted. */
    internal fun pushMembership(): Int {
        val dev = dir.load()
        val user = dev.enrolledUser ?: return 0
        // With the admitting op: a replica may not hold it (Go's no-replica layout), and an
        // op this device signed may cite it.
        val ops = Membership.merge(dir.ops(), listOf(dev.enrolmentCert!!))
        val body = MiniJson.encodeObject(listOf("ops" to WebLogin.presentable(ops))).encodeToByteArray()
        return settings.membershipRps.count { rp ->
            runCatching {
                http.post(rp.trimEnd('/') + "/membership/" + user, body, "application/json").status in HTTP_SUCCESS
            }.getOrDefault(false)
        }
    }

    private fun <T> outcome(o: PairingOutcome<T>): T = when (o) {
        is PairingOutcome.Ready -> o.value
        is PairingOutcome.Failed -> error(o.message)
    }

    private fun SealedDeviceKeys.asEd25519Signer() = deviceIdentity().asSigner()

    companion object {
        /** How long an invite waits for the new device: the relay's session TTL (10 min). */
        const val INVITE_WAIT_MILLIS = 10 * 60 * 1000L

        private val HTTP_SUCCESS = 200..299
        private const val SHORT_KEY_HEX = 8
        private const val SHORT_KEY_GROUP = 4
        private const val SAS_SPLIT_FROM = 7
        private const val SAS_HEAD = 3

        /** The first 8 hex digits of a key, in two groups: how the phone app names a device. */
        fun shortKey(rendered: String): String = Hex.encode(KeyRef.parse(rendered).bytes).uppercase()
            .take(SHORT_KEY_HEX).chunked(SHORT_KEY_GROUP).joinToString(" ")

        /** A security code split for reading aloud, as the phone app shows it. */
        fun formatSas(sas: String): String =
            if (sas.length >= SAS_SPLIT_FROM) "${sas.substring(0, SAS_HEAD)} ${sas.substring(SAS_HEAD)}" else sas

        /** A broker's audience: its origin, `scheme://host[:port]`. */
        fun originOf(url: String): String {
            val u = URI(url.trim())
            require(u.scheme != null && u.host != null) { "A broker must be an absolute URL: $url" }
            return u.scheme + "://" + u.host + (if (u.port >= 0) ":${u.port}" else "")
        }
    }
}
