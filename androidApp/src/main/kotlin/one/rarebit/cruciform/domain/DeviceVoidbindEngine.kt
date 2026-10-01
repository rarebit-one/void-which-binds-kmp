package one.rarebit.cruciform.domain

import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import one.rarebit.cruciform.BuildConfig
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.BiometricAuthenticator
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.platform.NotifyConfig
import one.rarebit.cruciform.platform.RelayConfig
import one.rarebit.cruciform.platform.StrongAuth
import one.rarebit.voidwhichbinds.AuthenticationRequiredException
import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.RecoverySecret
import one.rarebit.voidwhichbinds.UserFingerprint
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.VoidbindQr
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.flow.DeviceAuthorization
import one.rarebit.voidwhichbinds.flow.DevicePairing
import one.rarebit.voidwhichbinds.flow.LoginApproval
import one.rarebit.voidwhichbinds.flow.PairingFailures
import one.rarebit.voidwhichbinds.flow.PairingOutcome
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.NotifyClient
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy
import one.rarebit.voidwhichbinds.policy.ApprovalPolicyManager
import java.io.InterruptedIOException
import java.net.URI
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The real [VoidbindEngine]: wires the app UI to the library's commonMain device
 * brain (UserIdentity, DeviceIdentity, Enrolment, the flow coordinators) over the
 * hardware device key ([DeviceKeys]) + a sealed X25519 enc-key store ([IdentityStore]) and an
 * OkHttp [HttpTransport], gating every signature behind [BiometricAuthenticator].
 *
 * Every call runs on [Dispatchers.IO] through [ioResult], which turns any throw into
 * an [EngineResult.Failed] on that thread (never raw exception text) while letting a
 * coroutine cancellation propagate ([suspendRunCatching]). A hardware signature whose
 * auth window has lapsed throws [AuthenticationRequiredException]; [withDeviceAuth]
 * catches it, prompts, and retries once within the window — and if the human declines,
 * the step fails as CANCELLED.
 *
 * NOTE (device-tested, not CI): StrongBox non-extractability and the biometric gate
 * exist only on real hardware (docs/DEVICE-TESTING.md). This engine compiles and is
 * architecturally wired; its runtime behaviour is proven on a physical device, not
 * on an emulator or in CI. Both pairing directions are now UI-driven: the responder
 * (join → VERIFY → confirm) and the initiator (invite → [awaitPairHandshake] →
 * VERIFY → authorise).
 *
 * MEMBERSHIP (ADR-0005): this device is one member of the identity's device set.
 * "Add a device" is available to ANY member — the initiator signs the new device's
 * add op with its own hardware key, citing the heads of the replica in
 * [IdentityStore]; the recovery secret is only the genesis fallback for a device
 * whose own admission has lapsed. Login assertions present the replica (`ops`);
 * Settings → Devices evaluates it and can sign a `remove` (biometric-gated) that is
 * pushed to the relying parties in [membershipRps].
 */
class DeviceVoidbindEngine(
    private val store: IdentityStore,
    private val policyStore: ApprovalPolicyStore,
    private val transport: HttpTransport,
    private val biometric: BiometricAuthenticator,
    /**
     * The pairing-relay base this device MINTS invites through, read on every call —
     * a provider, not a value, so Settings → "Pairing relay" takes effect on the next
     * "Add a device" without recreating the engine (`RelaySettings.current`).
     */
    private val relay: () -> String,
    /**
     * The push/wake plane base this device REGISTERS its wake endpoint with, read on
     * every call — a provider, not a value, so Settings → "Push plane" takes effect on
     * the next registration (the next app open) without recreating the engine
     * (`NotifySettings.current`).
     */
    private val notify: () -> String = { DEFAULT_NOTIFY },
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
    /** Relying parties that serve `POST /membership/{usr}`; a remove is pushed to each, best-effort. */
    private val membershipRps: List<String> = DEFAULT_MEMBERSHIP_RPS,
    /** The hardware device signing key; a seam so the engine is unit-testable on the JVM. */
    private val deviceKeys: DeviceKeys = HardwareDeviceKeys(),
    /** The name a freshly provisioned/joined device takes (the handset model by default). */
    private val defaultDeviceName: () -> String = ::handsetName,
) : VoidbindEngine {

    /** The configured relay, resolved now (Settings may have changed it since the last call). */
    private val relayBase: String get() = relay()

    /** The configured push plane, resolved now (same reason as [relayBase]). */
    private val notifyBase: String get() = notify()

    /**
     * The relay a pending invite was MINTED against. The handshake/confirm steps
     * classify their failures against this, not [relayBase], so a Settings change
     * mid-flow cannot mislabel which relay dropped.
     */
    private var inviteRelay: String? = null

    // The per-RP approval policy + audit trail. Pure commonMain brain; [policyStore]
    // supplies persistence. It records consent AROUND the unchanged hardware signature.
    private val policy = ApprovalPolicyManager(policyStore, policyStore, clock)
    private val renewal = MembershipRenewal(deviceKeys, clock, ::dateLabel)
    private val recovery = RecoveryCopy(store, biometric, clock, ::dateLabel)
    private val _identity = MutableStateFlow<IdentityState>(IdentityState.Loading)
    override val identity: StateFlow<IdentityState> = _identity.asStateFlow()

    // In-session state for multi-step flows. (No user identity is cached here: the
    // genesis key is unsealed behind a strong biometric at each use and dropped after.)
    private var pendingLogin: Pair<LoginApproval, LoginApproval.Request>? = null
    private var pendingJoin: PendingJoin? = null
    private var pendingAuthorization: Pair<DeviceAuthorization, DeviceAuthorization.Invitation>? = null

    private class PendingJoin(
        val pairing: DevicePairing,
        val handshake: DevicePairing.Handshake,
        val enc: DeviceIdentity.EncryptionKey,
    )

    override suspend fun refresh(): EngineResult<Unit> = io("Couldn't load this device's identity.") {
        _identity.value = loadState()
    }

    // --- Onboarding -----------------------------------------------------------

    override suspend fun createIdentity(): EngineResult<RecoveryBackup> = io("Couldn't create the identity.") {
        provision(UserIdentity.create()).also {
            store.markBackupPending() // until the user confirms what they wrote down
            _identity.value = loadState()
        }
    }

    override suspend fun restoreIdentity(recoverySecret: String): EngineResult<Unit> = io(
        "That recovery secret could not be read.",
    ) {
        // A mistyped secret throws IllegalArgumentException from the parser; its message
        // (what was wrong with it) is what the Restore screen shows.
        provision(UserIdentity.restore(recoverySecret))
        store.markBackupChecked(clock()) // they just typed it: the written copy works
        _identity.value = loadState()
    }

    /**
     * Provision THIS device as the owner for [user]: hardware key, enc key, self-cert.
     * Then offer to keep the recovery secret on the phone. That copy is the genesis
     * authority, so it is sealed only behind a strong biometric: with none enrolled,
     * or the prompt declined, the phone keeps no copy and the written one is the only
     * one — the identity itself is provisioned either way.
     */
    private suspend fun provision(user: UserIdentity): RecoveryBackup {
        val enc = DeviceIdentity.generateEncryptionKey()
        val ks = withDeviceAuth { deviceKeys.getOrCreate() }
        val device = DeviceIdentity(ks.publicKey, enc.publicKey, enc.privateKey) { ks.sign(it) }
        val cert = Enrolment.selfEnrol(user, device, clock())
        store.saveOwner(cert, user.userPublicKey, enc.publicKey, enc.privateKey, defaultDeviceName())
        return backup(user).copy(keptOnDevice = recovery.offerToKeep(user.recovery))
    }

    override suspend fun revealRecoverySecret(): EngineResult<RecoveryBackup> =
        ioResult("Couldn't show the recovery secret.") {
            if (!store.hasUserKey()) return@ioResult notYetFailure("This device keeps no copy of the recovery secret.")
            when (val genesis = recovery.unsealGenesis("Show recovery secret")) {
                is EngineResult.Failed -> genesis
                is EngineResult.Ready -> EngineResult.Ready(backup(genesis.value).copy(keptOnDevice = true))
            }
        }

    override suspend fun splitRecoverySecret(): EngineResult<List<String>> =
        ioResult("Couldn't split the recovery secret.") { recovery.split() }

    override suspend fun verifyRecoverySecret(secret: String): EngineResult<RecoveryCheck> = ioResult(
        "That recovery secret could not be read.",
    ) {
        val persisted = store.load() ?: return@ioResult internalFailure("No identity on this device.")
        recovery.verify(secret, persisted).also { _identity.value = loadState() }
    }

    override suspend fun confirmBackup(): EngineResult<Unit> = io("Couldn't record the backup.") {
        store.markBackupChecked(clock())
        _identity.value = loadState()
    }

    override suspend fun forgetRecoverySecret(): EngineResult<Unit> = ioResult("Couldn't remove the recovery copy.") {
        val persisted = store.load() ?: return@ioResult internalFailure("No identity on this device.")
        val lapsed = renewal.health(persisted, deviceKeys.getOrCreate().publicKey).lapsed
        recovery.forget(lapsed).also { _identity.value = loadState() }
    }

    // --- Scanning -------------------------------------------------------------

    override fun parseScanned(raw: String): ScannedCode = try {
        when (val qr = VoidbindQr.parse(raw)) {
            is VoidbindQr.Login -> ScannedCode.WebLogin(qr.request.rp, qr.request.id, raw)
            is VoidbindQr.Pair -> ScannedCode.PairInvite(qr.invite.relay, qr.invite.session, raw)
        }
    } catch (_: Exception) {
        // Not a login or pairing code: perhaps the recovery sheet's QR (the secret in
        // upper case; the parser folds case and ignores whitespace, checksum included).
        scannedRecoverySecret(raw)
    }

    // --- Web login ------------------------------------------------------------

    override suspend fun fetchLoginRequest(code: ScannedCode.WebLogin): EngineResult<LoginRequest> = ioResult(
        LOGIN_UNREACHABLE,
        revealPreconditions = false,
    ) {
        val persisted = store.load()
            ?: return@ioResult internalFailure("No identity on this device.")
        // The assertion presents the replica (`ops`) beside the admitting op, so an RP
        // that never met the member that admitted this device can still evaluate it.
        val approval = LoginApproval(transport, buildDevice(), persisted.enrolmentCert, knownOps = persisted.ops)
        // beginCatching converts every transport/IO failure and non-2xx into an Outcome.Failed
        // instead of throwing, so an unreachable/misconfigured RP surfaces as a login error and
        // never becomes an uncaught main-thread FATAL. The extra suspendRunCatching is belt-and-braces:
        // no unexpected throw from this boundary may escape the approval coroutine.
        val outcome = suspendRunCatching { approval.beginCatching(LoginQr.Parsed(code.rpBase, code.loginId)) }
            .getOrElse { LoginApproval.Outcome.Failed(LoginApproval.FailureKind.UNREACHABLE, LOGIN_UNREACHABLE) }
        when (outcome) {
            is LoginApproval.Outcome.Failed -> {
                pendingLogin = null
                EngineResult.Failed(
                    EngineFailure(
                        outcome.message,
                        when (outcome.kind) {
                            LoginApproval.FailureKind.UNREACHABLE -> EngineFailure.Kind.UNREACHABLE
                            LoginApproval.FailureKind.EXPIRED -> EngineFailure.Kind.EXPIRED
                            LoginApproval.FailureKind.REJECTED -> EngineFailure.Kind.REJECTED
                        },
                    ),
                )
            }

            is LoginApproval.Outcome.Ready -> {
                val request = outcome.request
                pendingLogin = approval to request
                EngineResult.Ready(
                    LoginRequest(
                        domain = host(request.rp),
                        appName = "",
                        origin = request.audience,
                        signInAs = "${persisted.deviceName} · ${shortFingerprint(persisted.userPublicKey)}",
                        expiresInSeconds = (request.expiresAt - clock()).toInt().coerceAtLeast(0),
                        access = "Authentication only",
                        signatureValid = true,
                        candidates = request.candidates, // non-empty ⇒ a number-matching (push) login
                    ),
                )
            }
        }
    }

    // An approval's failure never shows the library's text ("weblogin: approve refused:
    // HTTP 403"): the RP refusing, the network dropping or nothing being pending all read
    // as one human message; a declined prompt reads as CANCELLED.
    override suspend fun approveLogin(code: ScannedCode.WebLogin): EngineResult<Unit> =
        io(SIGN_IN_FAILED, revealPreconditions = false) {
            val (approval, request) = pendingLogin ?: error("no login in progress")
            withDeviceAuth { approval.approve(request) }
            finishApproval(request, matchNumber = null)
        }

    override suspend fun approveNumberMatch(code: ScannedCode.WebLogin, chosen: Int): EngineResult<Unit> = io(
        SIGN_IN_FAILED,
        revealPreconditions = false,
    ) {
        val (approval, request) = pendingLogin ?: error("no login in progress")
        // approval.approve(request, chosen) signs the v2 binding; a decoy tap binds the
        // wrong number and the RP refuses it (thrown) — no site is recorded on refusal.
        withDeviceAuth { approval.approve(request, chosen) }
        finishApproval(request, matchNumber = chosen)
    }

    override suspend fun denyLogin(): EngineResult<Unit> = io("Couldn't record the denial.") {
        // The human declined. Nothing is signed; record the denial in the audit trail
        // (trust is untouched — a denial never trusts a site) and drop the pending login.
        pendingLogin?.let { (_, request) ->
            policy.recordDenial(host(request.rp), request.audience, request.loginId, matchNumber = null)
        }
        pendingLogin = null
    }

    private fun finishApproval(request: LoginApproval.Request, matchNumber: Int?) {
        val domain = host(request.rp)
        // Record the approval in the audit trail and apply trust-on-first-use. The
        // signature above is unchanged — this is consent/audit state around it.
        policy.recordApproval(domain, request.audience, request.loginId, matchNumber)
        store.upsertTrustedSite(TrustedSite(domain, domain, "", "just now", accentFor(domain)))
        pendingLogin = null
        // The device key was just unlocked to sign: the cheapest moment to renew.
        renewIfDue()
        _identity.value = loadState()
    }

    // --- Renewal (membership, ADR-0005) ----------------------------------------

    override suspend fun renewMembership(): EngineResult<Unit> = ioResult("Couldn't renew this device.") {
        val persisted = store.load() ?: return@ioResult internalFailure("No identity on this device.")
        val op = withDeviceAuth { renewal.selfRenewal(persisted, onlyIfDue = false) }
            ?: return@ioResult notYetFailure(
                "This device is no longer a member, so it can't renew itself. " +
                    "Re-admit it from another device, or restore from the recovery secret.",
            )
        recordRenewal(op)
        EngineResult.Ready(Unit)
    }

    /**
     * Renew this device if it is inside the renewal window, WITHOUT prompting: called
     * right after a signature, while the key's auth window is still open. Best effort —
     * a shut window or any failure just leaves the renewal for next time (or for the
     * user's "Renew now").
     */
    private fun renewIfDue() {
        val persisted = store.load() ?: return
        val op = runCatching { renewal.selfRenewal(persisted, onlyIfDue = true) }.getOrNull() ?: return
        runCatching { recordRenewal(op) }
    }

    private fun recordRenewal(op: String) {
        store.renewCredential(op)
        pushMembership(store.knownOps()) // best-effort; the renewal also travels with every login
        _identity.value = loadState()
    }

    // --- Push wake ------------------------------------------------------------

    // Best-effort, both ways: a failed wake registration just means no background push,
    // and scanned-QR login is unaffected, so callers log or ignore the Failed.
    override suspend fun registerForPush(endpoint: String): EngineResult<Unit> = ioResult(
        PUSH_FAILED,
        revealPreconditions = false,
    ) {
        val persisted = store.load() ?: return@ioResult internalFailure("No identity on this device.")
        // No plane configured (no build default, no Settings override): nothing to
        // register with — scanned-QR login works without a wake channel.
        val notifyBase = notifyBase.takeIf { it.isNotBlank() }
            ?: return@ioResult internalFailure("No push plane is set up.")
        NotifyClient(transport, notifyBase).subscribe(persisted.enrolmentCert, endpoint)
        EngineResult.Ready(Unit)
    }

    override suspend fun unregisterFromPush(): EngineResult<Unit> = ioResult(
        "Couldn't stop sign-in wake-ups for this device.",
        revealPreconditions = false,
    ) {
        val persisted = store.load() ?: return@ioResult EngineResult.Ready(Unit)
        val notifyBase = notifyBase.takeIf { it.isNotBlank() } ?: return@ioResult EngineResult.Ready(Unit)
        NotifyClient(transport, notifyBase).unsubscribe(persisted.enrolmentCert)
        EngineResult.Ready(Unit)
    }

    // --- Pairing --------------------------------------------------------------
    //
    // Every step below runs the BLOCKING relay transport on Dispatchers.IO and converts
    // any failure into an EngineResult.Failed ON THAT THREAD, inside [ioResult]'s
    // withContext block. That is the load-bearing part of the on-device crash fix: a call-site
    // runCatching in the UI did not save the app, because once the calling coroutine
    // (a LaunchedEffect) had been cancelled, the SocketTimeoutException the blocking
    // call threw 15s later had no caller to be delivered to and went to the uncaught
    // handler as a main-thread FATAL. Nothing may throw out of these blocks.

    override suspend fun startPairInvite(): EngineResult<PairInviteDisplay> = withContext(Dispatchers.IO) {
        // Read the relay ONCE per invite: Settings → "Pairing relay" is consulted here, at
        // invite time, so a change applies to the next invite with no restart.
        val relayBase = relayBase
        inviteRelay = relayBase
        if (relayBase.isBlank()) {
            // This build ships no default relay and Settings holds none: say so (the
            // dialog offers "Change relay") rather than dialling an empty URL.
            return@withContext EngineResult.Failed(
                EngineFailure(
                    "No pairing relay is set up. Add one in Settings → Pairing relay.",
                    EngineFailure.Kind.REJECTED,
                    retryable = false,
                ),
            )
        }
        ioResult(PAIRING_FAILED, relayBase) {
            val authorization = when (val a = memberAuthorization()) {
                is EngineResult.Failed -> return@ioResult a
                is EngineResult.Ready -> a.value
            }
            when (val outcome = authorization.inviteCatching(relayBase)) {
                is PairingOutcome.Failed -> EngineResult.Failed(outcome.toEngineFailure())

                is PairingOutcome.Ready -> {
                    val invitation = outcome.value
                    pendingAuthorization = authorization to invitation
                    EngineResult.Ready(
                        PairInviteDisplay(
                            inviteId = "INV · ${invitation.relaySession.uppercase().take(
                                8,
                            ).chunked(4).joinToString(" ")}",
                            qrPayload = invitation.inviteQr,
                            expiresInSeconds = INVITE_TTL_SECONDS,
                            // The relay session the invite names: an RP on this phone
                            // reports it back over the one-tap callback (ADR-0008).
                            session = invitation.relaySession,
                        ),
                    )
                }
            }
        }
    }

    override suspend fun awaitPairHandshake(): EngineResult<PairSession> = ioResult(
        PAIRING_FAILED,
        inviteRelay ?: relayBase,
    ) {
        val (authorization, invitation) = pendingAuthorization
            ?: return@ioResult internalFailure("No pairing invite is in progress.")
        // Blocks (polls the relay) until the new device joins and both sides
        // commit → reveal → open; returns the SAS. Signs nothing yet — the human
        // matches this against the new device's screen, then confirmPairing()
        // authorises. handshake() flips the initiator's `handshook` flag so the
        // subsequent authorise() on the SAME invitation is valid.
        when (val outcome = authorization.handshakeCatching(invitation)) {
            is PairingOutcome.Failed -> EngineResult.Failed(outcome.toEngineFailure())

            is PairingOutcome.Ready -> EngineResult.Ready(
                PairSession(
                    thisDeviceName = defaultDeviceName(),
                    peerDeviceName = "New device",
                    securityCode = formatSas(outcome.value),
                    // What the RELAY revealed. The one-tap path (ADR-0008) checks the
                    // RP's own local report against this; a mismatch signs nothing.
                    peerDeviceKey = invitation.responderDeviceId,
                ),
            )
        }
    }

    override suspend fun joinPairInvite(code: ScannedCode.PairInvite): EngineResult<PairSession> = ioResult(
        PAIRING_FAILED,
        code.relay,
    ) {
        val ks = withDeviceAuth { deviceKeys.getOrCreate() }
        val enc = existingEncKey() ?: DeviceIdentity.generateEncryptionKey()
        val device = DeviceIdentity(ks.publicKey, enc.publicKey, enc.privateKey) { ks.sign(it) }
        val pairing = DevicePairing(transport, device, clock)
        // beginCatching turns the blocking relay handshake's every failure (no route,
        // refused, TLS, timeout, relay non-2xx, a commitment that does not open) into a
        // classified outcome instead of throwing — the SocketTimeoutException that
        // killed the app arrived through exactly this call.
        when (val outcome = pairing.beginCatching(code.raw)) {
            is PairingOutcome.Failed -> {
                pendingJoin = null
                EngineResult.Failed(outcome.toEngineFailure())
            }

            is PairingOutcome.Ready -> {
                val handshake = outcome.value
                pendingJoin = PendingJoin(pairing, handshake, enc)
                EngineResult.Ready(
                    PairSession(
                        thisDeviceName = defaultDeviceName(),
                        peerDeviceName = "New device",
                        securityCode = formatSas(handshake.sas),
                    ),
                )
            }
        }
    }

    override suspend fun confirmPairing(): EngineResult<Unit> = ioResult(
        PAIRING_FAILED,
        inviteRelay ?: relayBase,
    ) {
        val join = pendingJoin
        if (join != null) {
            if (!biometric.authenticate("Confirm pairing", "Approve on this device")) {
                return@ioResult cancelledFailure()
            }
            return@ioResult when (val outcome = join.pairing.confirmCatching(join.handshake)) {
                is PairingOutcome.Failed -> EngineResult.Failed(outcome.toEngineFailure())

                is PairingOutcome.Ready -> {
                    // The admission: this device's admitting op (its credential) plus
                    // the ops that authorise it (its replica from here on).
                    val admission = outcome.value
                    val userPub = KeyRef.parse(MembershipOp.verify(admission.op).user).bytes
                    store.saveJoined(
                        admission.op,
                        admission.ops,
                        userPub,
                        join.enc.publicKey,
                        join.enc.privateKey,
                        defaultDeviceName(),
                    )
                    pendingJoin = null
                    _identity.value = loadState()
                    EngineResult.Ready(Unit)
                }
            }
        }
        val authorization = pendingAuthorization
        if (authorization != null) {
            // Admitting a new member is an authority act — strong biometric only, no
            // PIN fallback, so a thief with the screen-lock secret can't enrol their
            // own device. (The responder path above only adds THIS device and keeps
            // the softer presence check.)
            when (biometric.authenticateStrong("Authorise new device", "Confirm with your fingerprint or face")) {
                StrongAuth.SUCCESS -> Unit
                StrongAuth.CANCELLED -> return@ioResult cancelledFailure()
                StrongAuth.UNAVAILABLE -> return@ioResult strongBiometricRequiredFailure()
            }
            // authorise() SIGNS the add with this device's hardware key (a member
            // initiator) — so it runs under withDeviceAuth, which re-prompts if the
            // keystore's auth window has lapsed; any throw lands in ioResult.
            val ops = withDeviceAuth { authorization.first.authorise(authorization.second) }
            store.recordOps(ops)
            pendingAuthorization = null
            pushMembership(ops) // best-effort: the RPs learn the new member now, not at its first login
            renewIfDue() // the key was just unlocked to sign the add
            _identity.value = loadState()
            return@ioResult EngineResult.Ready(Unit)
        }
        internalFailure("No pairing is in progress.")
    }

    /**
     * The engine's one error boundary. Runs [block] on [Dispatchers.IO] and turns
     * whatever it throws that the library's `*Catching` layer did not already classify
     * (a keystore error, a missing precondition, a transport failure, a bug) into a
     * `Failed` there, on the IO thread, so it can never escape the coroutine — see
     * [failureOf]. [suspendRunCatching] rethrows a [kotlinx.coroutines.CancellationException],
     * so a cancelled caller is still torn down rather than handed a failure.
     *
     * [relayBase] marks a pairing step: an unclassified throw is then read against that
     * relay (unreachable / refused / protocol). [revealPreconditions] lets a
     * precondition's own message (`check`/`require`/`error`) through; turn it off where
     * such messages are library-internal (an RP's HTTP status), so only [fallback] shows.
     */
    private suspend fun <T> ioResult(
        fallback: String,
        relayBase: String? = null,
        revealPreconditions: Boolean = true,
        block: suspend () -> EngineResult<T>,
    ): EngineResult<T> = withContext(Dispatchers.IO) {
        suspendRunCatching { block() }
            .getOrElse { EngineResult.Failed(failureOf(it, fallback, relayBase, revealPreconditions)) }
    }

    /** [ioResult] for a step whose success is a plain value. */
    private suspend fun <T> io(
        fallback: String,
        revealPreconditions: Boolean = true,
        block: suspend () -> T,
    ): EngineResult<T> = ioResult(fallback, revealPreconditions = revealPreconditions) { EngineResult.Ready(block()) }

    /** Classify a throw that reached [ioResult]. Never raw exception text for an unexpected throw. */
    private fun failureOf(
        e: Throwable,
        fallback: String,
        relayBase: String?,
        revealPreconditions: Boolean,
    ): EngineFailure {
        fun precondition() = EngineFailure(
            (if (revealPreconditions) e.message else null) ?: fallback,
            EngineFailure.Kind.INTERNAL,
            retryable = false,
        )
        return when {
            // The keystore wanted a fresh authentication and the human declined the prompt.
            e is AuthenticationRequiredException -> CANCELLED_FAILURE

            // A gen1 sheet typed into Restore or the drill: retired, not mistyped (ADR-0022).
            e is RecoverySecret.GenerationRetiredException -> RETIRED_RECOVERY_FAILURE

            // check()/error() in this engine: "no identity", "no login in progress", "This
            // device is no longer a member…" — a precondition, not a network problem.
            e is IllegalStateException -> precondition()

            // require() in the library's parsers ("not a valid recovery secret: …").
            relayBase == null && e is IllegalArgumentException -> precondition()

            relayBase == null -> precondition().copy(message = fallback)

            // The blocking relay call was interrupted (the thread, not the network): this is
            // NOT "can't reach the relay" — the relay never answered badly. Distinct kind so
            // the dialog doesn't send the user to check Wi-Fi.
            e is InterruptedIOException || e is InterruptedException -> EngineFailure(
                "The pairing was interrupted. Start again with a fresh invite.",
                EngineFailure.Kind.CANCELLED,
                retryable = true,
            )

            else -> PairingFailures.classify(e, relayBase).toEngineFailure()
        }
    }

    // Declining signs with this device's key, so it is gated like any signature. A
    // cancelled prompt still ends the invite, locally only: the other device then waits
    // out its own timeout, as before ADR-0012.
    override suspend fun refusePairing(): EngineResult<Unit> = ioResult(PAIRING_FAILED, inviteRelay ?: relayBase) {
        val (authorization, invitation) = pendingAuthorization
            ?: return@ioResult internalFailure("No pairing invite is in progress.")
        pendingAuthorization = null
        if (!biometric.authenticate("Decline new device", "Tell the other device the codes didn't match")) {
            return@ioResult cancelledFailure()
        }
        val sent = withDeviceAuth { authorization.refuseCatching(invitation) }
        if (sent is PairingOutcome.Failed) EngineResult.Failed(sent.toEngineFailure()) else EngineResult.Ready(Unit)
    }

    // --- Devices (membership, ADR-0005) ---------------------------------------

    override suspend fun devices(): EngineResult<List<MemberDevice>> =
        ioResult("Couldn't load this identity's devices.") {
            val persisted = store.load() ?: return@ioResult EngineResult.Ready(emptyList())
            val usr = KeyRef.ed25519(persisted.userPublicKey).render()
            val self = KeyRef.ed25519(deviceKeys.getOrCreate().publicKey).render()
            val view = Membership.evaluate(usr, persisted.ops, clock())
            val members = view.members.values
                .sortedWith(compareBy<Membership.Member> { it.device != self }.thenBy { it.admittedAt })
                .map { m ->
                    val admitting = view.accepted[m.admittedBy]
                    MemberDevice(
                        id = m.device,
                        fingerprint = shortFingerprint(KeyRef.parse(m.device).bytes),
                        isThisDevice = m.device == self,
                        admittedByLabel = when {
                            admitting == null -> "unknown"
                            admitting.genesis -> "genesis (recovery key)"
                            admitting.by == self -> "this device"
                            else -> shortFingerprint(KeyRef.parse(admitting.by).bytes)
                        },
                        admittedLabel = dateLabel(m.admittedAt),
                        expiresLabel = "renews by ${dateLabel(m.expiresAt)}",
                    )
                }
            EngineResult.Ready(members)
        }

    override suspend fun removeDevice(deviceId: String): EngineResult<Unit> = ioResult(
        "Couldn't remove the device.",
        relayBase,
    ) {
        val persisted = store.load() ?: return@ioResult internalFailure("No identity on this device.")
        val ks = deviceKeys.getOrCreate()
        val selfPub = ks.publicKey
        val self = KeyRef.ed25519(selfPub).render()
        if (deviceId == self) {
            return@ioResult internalFailure("This device can't remove itself. Remove it from another device.")
        }
        val usr = KeyRef.ed25519(persisted.userPublicKey).render()
        val now = clock()
        val view = Membership.evaluate(usr, persisted.ops, now)
        if (!view.isMember(self)) {
            return@ioResult internalFailure("This device is no longer a member, so it can't remove others.")
        }
        if (!view.isMember(deviceId)) return@ioResult internalFailure("That device is not a member any more.")
        // Strong biometric only, no PIN fallback: an unlocked stolen phone whose
        // screen-lock secret is known must NOT be able to purge the fleet (ADR-0005 —
        // seniority alone can't tell owner from thief; this is the "biometric on
        // remove" mitigation).
        when (biometric.authenticateStrong("Remove device", "Confirm with your fingerprint or face")) {
            StrongAuth.SUCCESS -> Unit
            StrongAuth.CANCELLED -> return@ioResult cancelledFailure()
            StrongAuth.UNAVAILABLE -> return@ioResult strongBiometricRequiredFailure()
        }
        // The remove is signed by THIS device's hardware key, citing the replica's heads —
        // the causal evidence that it was a member when it said so (ADR-0005 rule 2).
        val removeOp = withDeviceAuth {
            MembershipOp.sign(
                { ks.sign(it) },
                selfPub,
                usr,
                MembershipOp.Kind.REMOVE,
                dev = deviceId,
                deviceEnc = "",
                prev = view.heads,
                issuedAt = now,
            )
        }
        store.recordOps(listOf(removeOp))
        val ops = store.knownOps()
        check(!Membership.evaluate(usr, ops, now).isMember(deviceId)) { "the removal did not take effect locally" }
        pushMembership(ops)
        _identity.value = loadState()
        EngineResult.Ready(Unit)
    }

    /**
     * Push the replica to every relying party this app knows (`POST /membership/{usr}
     * {"ops":[…]}` — heyarr-core / All Thing), so a remove reaches them now rather than
     * at some device's next authenticated call. Best-effort by design: an RP that is
     * unreachable, or does not serve the route yet (404), is skipped — the ops still
     * travel with every login assertion. Returns how many RPs accepted.
     */
    private fun pushMembership(ops: List<String>): Int {
        val persisted = store.load() ?: return 0
        val usr = KeyRef.ed25519(persisted.userPublicKey).render()
        val body = MiniJson.encodeObject(
            listOf("ops" to one.rarebit.voidwhichbinds.WebLogin.presentable(ops)),
        ).encodeToByteArray()
        var accepted = 0
        for (rp in membershipRps) {
            val ok = runCatching {
                transport.post(rp.trimEnd('/') + "/membership/" + usr, body, "application/json").status in 200..299
            }.getOrDefault(false)
            if (ok) accepted++
        }
        return accepted
    }

    private fun dateLabel(unixSeconds: Long): String =
        SimpleDateFormat("d MMM yyyy", Locale.getDefault()).format(Date(unixSeconds * 1000))

    // --- Settings -------------------------------------------------------------

    override suspend fun renameDevice(name: String): EngineResult<Unit> = io("Couldn't rename this device.") {
        store.setDeviceName(name)
        _identity.value = loadState()
    }

    override suspend fun setBiometricApproval(enabled: Boolean): EngineResult<Unit> =
        io("Couldn't change biometric approval.") {
            store.setBiometricApproval(enabled)
            _identity.value = loadState()
        }

    override suspend fun revokeSite(siteId: String): EngineResult<Unit> = io("Couldn't revoke $siteId.") {
        store.removeTrustedSite(siteId)
        policy.forget(siteId) // the site's TrustedSite.id is its host, the policy key
        _identity.value = loadState()
    }

    // --- Per-RP approval policy + audit ---------------------------------------

    override suspend fun sitePolicy(rp: String): EngineResult<SitePolicyView> =
        io("Couldn't read $rp's approval policy.") {
            val p = policy.policyFor(rp)
            SitePolicyView(
                rp = rp,
                policy = p?.policy ?: ApprovalPolicy.AlwaysAsk,
                pinnedAlwaysAsk = p?.pinnedAlwaysAsk ?: false,
            )
        }

    override suspend fun setAlwaysAsk(rp: String, alwaysAsk: Boolean): EngineResult<Unit> = io(
        "Couldn't change $rp's approval policy.",
    ) {
        if (alwaysAsk) policy.setAlwaysAsk(rp) else policy.trust(rp)
        _identity.value = loadState()
    }

    override suspend fun approvalActivity(limit: Int): EngineResult<List<ApprovalActivity>> = io(
        "Couldn't load the approval activity.",
    ) {
        val now = clock()
        policy.auditEntries(limit).map { ApprovalActivity.from(it, relativeTime(now, it.timestampSeconds)) }
    }

    // --- internals ------------------------------------------------------------

    private fun loadState(): IdentityState {
        val persisted = store.load() ?: return IdentityState.None
        val ks = deviceKeys.getOrCreate()
        val devicePub = ks.publicKey
        val backing = ks.backing()
        return IdentityState.Active(
            identity = Identity(
                label = persisted.deviceName, // the enrolled/chosen device name — never a leftover tag
                fingerprint = UserFingerprint.of(persisted.userPublicKey),
                fullKey = one.rarebit.voidwhichbinds.KeyRef.ed25519(persisted.userPublicKey).render(),
                offlineVerifiable = true,
            ),
            device = DeviceInfo(
                name = persisted.deviceName,
                label = "dev · ${shortFingerprint(devicePub)}",
                backing = backing, // the REAL tier queried from the wrapping key, not assumed
                biometricRequired = persisted.biometricApproval,
            ),
            trustedSites = store.trustedSites().map { site ->
                // Join the per-RP policy (kept in a separate store) onto each site row.
                val p = policyStore.get(site.id)
                site.copy(
                    policy = p?.policy ?: ApprovalPolicy.AlwaysAsk,
                    pinnedAlwaysAsk = p?.pinnedAlwaysAsk ?: false,
                )
            },
            biometricApproval = persisted.biometricApproval,
            holdsRecoverySecret = store.hasUserKey(),
            membership = renewal.health(persisted, devicePub),
            backup = recovery.status(),
        )
    }

    /** A coarse "just now / 5m ago / 3h ago / 2d ago" label from two unix-seconds stamps. */
    private fun relativeTime(now: Long, then: Long): String {
        val secs = (now - then).coerceAtLeast(0)
        return when {
            secs < 60 -> "just now"
            secs < 3_600 -> "${secs / 60}m ago"
            secs < 86_400 -> "${secs / 3_600}h ago"
            else -> "${secs / 86_400}d ago"
        }
    }

    private fun buildDevice(): DeviceIdentity {
        val ks = deviceKeys.getOrCreate()
        val persisted = store.load() ?: error("no identity on this device")
        val encPriv = store.encPrivateKey() ?: error("device encryption key missing")
        return DeviceIdentity(ks.publicKey, persisted.encPublicKey, encPriv) { ks.sign(it) }
    }

    private fun existingEncKey(): DeviceIdentity.EncryptionKey? {
        val priv = store.encPrivateKey() ?: return null
        val pub = store.load()?.encPublicKey ?: return null
        return DeviceIdentity.EncryptionKey(priv, pub)
    }

    /**
     * The authority for "Add a device": THIS device as a member (ADR-0005 — no secret
     * involved), signing with its hardware key and citing the heads of its replica.
     * Only if its own ops no longer find it a member (its add lapsed, or it was
     * removed) does an install that holds the recovery secret fall back to GENESIS,
     * which is the one authority that can re-admit — a Restore-based install is
     * exactly that case.
     */
    private suspend fun memberAuthorization(): EngineResult<DeviceAuthorization> {
        val persisted = store.load() ?: error("No identity on this device.")
        val device = buildDevice()
        val usr = KeyRef.ed25519(persisted.userPublicKey).render()
        val view = Membership.evaluate(usr, persisted.ops, clock())
        if (view.isMember(device.deviceId.render())) {
            return EngineResult.Ready(
                DeviceAuthorization(
                    transport,
                    device,
                    persisted.enrolmentCert,
                    persisted.ops,
                    clock,
                    maxWaitMillis = INVITE_TTL_SECONDS * 1000L,
                ),
            )
        }
        check(store.hasUserKey()) {
            "This device is no longer a member of the identity, so it can't add devices. Re-admit it from another device, or restore from the recovery secret."
        }
        return when (val genesis = recovery.unsealGenesis("Add a device with your recovery key")) {
            is EngineResult.Failed -> genesis

            is EngineResult.Ready -> EngineResult.Ready(
                DeviceAuthorization(
                    transport,
                    genesis.value,
                    clock,
                    knownOps = persisted.ops,
                    maxWaitMillis = INVITE_TTL_SECONDS * 1000L,
                ),
            )
        }
    }

    private suspend fun <T> withDeviceAuth(block: () -> T): T = try {
        block()
    } catch (e: AuthenticationRequiredException) {
        if (biometric.authenticate("Authenticate", "Confirm it's you to use your device key")) {
            block()
        } else {
            throw e
        }
    }

    private fun backup(user: UserIdentity): RecoveryBackup {
        val rendered = user.recovery.format()
        return RecoveryBackup(
            groupedSecret = rendered.chunked(4).joinToString(" "),
            rawSecret = rendered,
            fingerprint = user.fingerprint,
            userId = user.userId.render(),
        )
    }

    private fun shortFingerprint(pub: ByteArray): String =
        Hex.encode(pub).uppercase().take(8).chunked(4).joinToString(" ")

    private fun formatSas(sas: String): String =
        if (sas.length >= 7) "${sas.substring(0, 3)} ${sas.substring(3)}" else sas

    private fun host(url: String): String = try {
        URI(url).host ?: url
    } catch (_: Throwable) {
        url
    }

    private fun accentFor(key: String): SiteAccent =
        SiteAccent.entries[(key.hashCode() and 0x7fffffff) % SiteAccent.entries.size]

    companion object {
        /**
         * How long a minted invite waits for the new device, and the initiator's relay
         * poll bound: the relay's session TTL (void-which-binds-go `relay.DefaultSessionTTL`,
         * 10 min on the heyarr node). The new device may have to be created first — a
         * key behind a fingerprint in another app — so the wait is human-paced, not
         * transport-paced (the library default of 60 s stranded every same-phone
         * enrolment: the initiator gave up before the responder posted its commit).
         */
        const val INVITE_TTL_SECONDS = 600

        private const val PAIRING_FAILED = "Couldn't complete the pairing."
        private const val SIGN_IN_FAILED = "Couldn't complete the sign-in."
        private const val LOGIN_UNREACHABLE = "Couldn't reach the site."
        private const val PUSH_FAILED = "Couldn't register this device for sign-in wake-ups."

        /**
         * The default pairing relay when Settings holds no override — a build-time value,
         * `""` when the build carries none (see [RelayConfig.DEFAULT_RELAY]).
         */
        val DEFAULT_RELAY: String get() = RelayConfig.DEFAULT_RELAY

        /**
         * The default push/wake plane when Settings holds no override — a build-time
         * value, `""` when the build carries none (see [NotifyConfig.DEFAULT_NOTIFY]).
         */
        val DEFAULT_NOTIFY: String get() = NotifyConfig.DEFAULT_NOTIFY

        /**
         * Relying parties that serve `POST /membership/{usr}` (heyarr-core, All Thing):
         * best-effort targets for a pushed remove/add; a 404 from one that has not landed
         * the route yet is tolerated. A build-time, comma-separated list
         * (`BuildConfig.DEFAULT_MEMBERSHIP_RPS`, from `CRUCIFORM_MEMBERSHIP_RPS` /
         * `cruciformMembershipRps`) — empty by default, in which case a remove simply
         * travels with the next login assertion instead of being pushed.
         */
        val DEFAULT_MEMBERSHIP_RPS: List<String> =
            BuildConfig.DEFAULT_MEMBERSHIP_RPS.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }
}

/** "<manufacturer> <model>", or "This device" when the handset reports neither. */
private fun handsetName(): String {
    val name = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
    return name.ifBlank { "This device" }
}
