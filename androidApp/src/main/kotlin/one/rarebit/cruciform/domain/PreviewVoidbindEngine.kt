package one.rarebit.cruciform.domain

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy
import one.rarebit.voidwhichbinds.policy.ApprovalPolicyManager
import one.rarebit.voidwhichbinds.policy.InMemoryApprovalAuditLog
import one.rarebit.voidwhichbinds.policy.InMemorySitePolicyStore

/**
 * A fully in-memory engine seeded with the mockup data, so the entire UI runs and
 * looks exactly like the design before the real coordinators + hardware are wired.
 * Used by @Preview and as the app's initial backend. It performs NO cryptography and
 * NO I/O — it is scaffolding, and every value here is placeholder content, not a
 * real identity. The real [VoidbindEngine] replaces it as a single DI swap.
 */
class PreviewVoidbindEngine(initial: IdentityState = SampleData.activeState) : VoidbindEngine {

    private val _identity = MutableStateFlow(initial)
    override val identity: StateFlow<IdentityState> = _identity.asStateFlow()

    // A real (in-memory) policy manager so the preview exercises TOFU + the audit log
    // exactly as the device engine does, just without persistence or a clock of record.
    private var previewClock = 1_724_000_000L
    private val policy = ApprovalPolicyManager(InMemorySitePolicyStore(), InMemoryApprovalAuditLog()) { previewClock }

    init {
        // Seed a plausible activity history + one trusted site so the log/settings screens
        // have something to render under @Preview.
        policy.trust("thesim.family")
        policy.recordApproval("thesim.family", "https://thesim.family", "L-1001")
        previewClock += 3_600
        policy.recordDenial("unknown.example", "https://unknown.example", "L-1002")
    }

    override suspend fun refresh(): EngineResult<Unit> = EngineResult.Ready(Unit) // already seeded

    override suspend fun createIdentity(): EngineResult<RecoveryBackup> {
        delay(400)
        _identity.value = SampleData.activeState
        return EngineResult.Ready(SampleData.recoveryBackup)
    }

    override suspend fun restoreIdentity(recoverySecret: String): EngineResult<Unit> {
        delay(400)
        _identity.value = SampleData.activeState
        return EngineResult.Ready(Unit)
    }

    override suspend fun revealRecoverySecret(): EngineResult<RecoveryBackup> {
        delay(200)
        return EngineResult.Ready(SampleData.recoveryBackup)
    }

    // A throwaway secret split for real, so the preview shows genuine 33-word shares.
    override suspend fun splitRecoverySecret(): EngineResult<List<String>> {
        delay(400)
        return EngineResult.Ready(UserIdentity.create().recovery.splitShares())
    }

    override fun parseScanned(raw: String): ScannedCode = when {
        raw.startsWith("voidbind:login") -> ScannedCode.WebLogin("https://thesim.family", "sample-login-id", raw)
        raw.startsWith("voidbind:pair") -> ScannedCode.PairInvite("wss://relay.thesim.family", "sample-session", raw)
        raw.lowercase().startsWith("heyarr1") -> ScannedCode.RecoverySecret(raw)
        else -> ScannedCode.Unknown(raw)
    }

    override suspend fun fetchLoginRequest(code: ScannedCode.WebLogin): EngineResult<LoginRequest> {
        delay(300)
        return EngineResult.Ready(SampleData.loginRequest)
    }

    override suspend fun approveLogin(code: ScannedCode.WebLogin): EngineResult<Unit> = done(600)

    override suspend fun approveNumberMatch(code: ScannedCode.WebLogin, chosen: Int): EngineResult<Unit> = done(600)

    override suspend fun denyLogin(): EngineResult<Unit> = done(100)

    override suspend fun registerForPush(endpoint: String): EngineResult<Unit> = done(150)

    override suspend fun unregisterFromPush(): EngineResult<Unit> = done(150)

    /** A step that just takes a moment and succeeds. */
    private suspend fun done(millis: Long): EngineResult<Unit> {
        delay(millis)
        return EngineResult.Ready(Unit)
    }

    override suspend fun startPairInvite(): EngineResult<PairInviteDisplay> {
        delay(200)
        return EngineResult.Ready(SampleData.pairInvite)
    }

    override suspend fun awaitPairHandshake(): EngineResult<PairSession> {
        delay(1500) // stand in for the new device joining the relay + handshake
        return EngineResult.Ready(SampleData.pairSession)
    }

    override suspend fun joinPairInvite(code: ScannedCode.PairInvite): EngineResult<PairSession> {
        delay(500)
        // The preview never touches a network; an invite naming an unreachable-looking
        // relay renders the same error the device engine would, so the dialog is
        // reviewable without hardware.
        if (code.relay.contains("unreachable")) {
            return EngineResult.Failed(
                EngineFailure(
                    "Can't reach the relay at ${code.relay.substringAfter(
                        "://",
                    ).substringBefore("/")}. Check Wi-Fi or your VPN and try again.",
                    EngineFailure.Kind.UNREACHABLE,
                ),
            )
        }
        return EngineResult.Ready(SampleData.pairSession)
    }

    override suspend fun refusePairing(): EngineResult<Unit> = EngineResult.Ready(Unit)

    override suspend fun confirmPairing(): EngineResult<Unit> {
        delay(600)
        return EngineResult.Ready(Unit)
    }

    private val previewDevices = SampleData.devices.toMutableList()

    override suspend fun devices(): EngineResult<List<MemberDevice>> {
        delay(100)
        return EngineResult.Ready(previewDevices.toList())
    }

    override suspend fun verifyRecoverySecret(secret: String): EngineResult<RecoveryCheck> {
        delay(400)
        return EngineResult.Ready(RecoveryCheck("PYJI XGNZ K7ZH XHEJ"))
    }

    override suspend fun confirmBackup(): EngineResult<Unit> = EngineResult.Ready(Unit)

    override suspend fun forgetRecoverySecret(): EngineResult<Unit> {
        delay(400)
        return EngineResult.Ready(Unit)
    }

    override suspend fun renewMembership(): EngineResult<Unit> {
        delay(400)
        return EngineResult.Ready(Unit)
    }

    override suspend fun removeDevice(deviceId: String): EngineResult<Unit> {
        delay(400)
        if (previewDevices.firstOrNull { it.id == deviceId }?.isThisDevice == true) {
            return EngineResult.Failed(
                EngineFailure("This device can't remove itself.", EngineFailure.Kind.INTERNAL, retryable = false),
            )
        }
        previewDevices.removeAll { it.id == deviceId }
        return EngineResult.Ready(Unit)
    }

    override suspend fun renameDevice(name: String): EngineResult<Unit> {
        _identity.update { s ->
            if (s is IdentityState.Active) s.copy(device = s.device.copy(name = name)) else s
        }
        return EngineResult.Ready(Unit)
    }

    override suspend fun setBiometricApproval(enabled: Boolean): EngineResult<Unit> {
        _identity.update { s -> if (s is IdentityState.Active) s.copy(biometricApproval = enabled) else s }
        return EngineResult.Ready(Unit)
    }

    override suspend fun revokeSite(siteId: String): EngineResult<Unit> {
        policy.forget(siteId)
        _identity.update { s ->
            if (s is IdentityState.Active) s.copy(trustedSites = s.trustedSites.filterNot { it.id == siteId }) else s
        }
        return EngineResult.Ready(Unit)
    }

    override suspend fun sitePolicy(rp: String): EngineResult<SitePolicyView> {
        val p = policy.policyFor(rp)
        val view = SitePolicyView(rp, p?.policy ?: ApprovalPolicy.AlwaysAsk, p?.pinnedAlwaysAsk ?: false)
        return EngineResult.Ready(view)
    }

    override suspend fun setAlwaysAsk(rp: String, alwaysAsk: Boolean): EngineResult<Unit> {
        if (alwaysAsk) policy.setAlwaysAsk(rp) else policy.trust(rp)
        return EngineResult.Ready(Unit)
    }

    override suspend fun approvalActivity(limit: Int): EngineResult<List<ApprovalActivity>> =
        EngineResult.Ready(policy.auditEntries(limit).map { ApprovalActivity.from(it, whenLabel = "recently") })
}

/** Sample content mirroring the product mockups. Placeholder only. */
object SampleData {
    val identity = Identity(
        label = "Jaryl's Nothing Phone",
        fingerprint = "7C4A 91D2 0E8F",
        fullKey = "ed25519:7c4a91d20e8f5b3a2c1d4e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b",
        offlineVerifiable = true,
    )

    val device = DeviceInfo(
        name = "Jaryl's Nothing Phone",
        label = "dev · A29F 67B1",
        backing = HardwareBacking.STRONGBOX,
        biometricRequired = true,
    )

    val trustedSites = listOf(
        TrustedSite(
            "thesim",
            "thesim.family",
            "All Thing",
            "last used today",
            SiteAccent.BLUE,
            policy = ApprovalPolicy.TrustedTofu,
        ),
        TrustedSite(
            "cove",
            "home.cove.lan",
            "Cove Control",
            "yesterday",
            SiteAccent.PURPLE,
            policy = ApprovalPolicy.AlwaysAsk,
            pinnedAlwaysAsk = true,
        ),
        TrustedSite(
            "bartley",
            "bartley.home",
            "Home Assistant",
            "6 days ago",
            SiteAccent.MINT,
            policy = ApprovalPolicy.TrustedTofu,
        ),
    )

    val activeState = IdentityState.Active(
        identity = identity,
        device = device,
        trustedSites = trustedSites,
        biometricApproval = true,
    )

    val recoveryBackup = RecoveryBackup(
        groupedSecret = "heyarr1 r9k7 x4pm 2qvt 8c3n h6wy f0ad j5se u2lz",
        rawSecret = "heyarr1r9k7x4pm2qvt8c3nh6wyf0adj5seu2lz",
        fingerprint = "PYJI XGNZ K7ZH XHEJ",
        userId = "ed25519:7c4a91d20e8f00000000000000000000000000000000000000000000000000ff",
    )

    val loginRequest = LoginRequest(
        domain = "thesim.family",
        appName = "All Thing",
        origin = "https://thesim.family",
        signInAs = "Jaryl's Nothing Phone · 7C4A…0E8F",
        expiresInSeconds = 58,
        access = "Authentication only",
        signatureValid = true,
    )

    /** A push-woken, number-matching login: the phone shows candidates, the user taps the match. */
    val numberMatchRequest = loginRequest.copy(candidates = listOf(27, 84, 61))

    val pairInvite = PairInviteDisplay(
        inviteId = "INV · 8F2C 91A7",
        qrPayload = "voidbind:pair?v=3&relay=wss://relay.thesim.family&session=8f2c91a7&salt=…&usr=ed25519:…",
        expiresInSeconds = 278,
    )

    val devices = listOf(
        MemberDevice(
            id = "ed25519:a29f67b1000000000000000000000000000000000000000000000000000000a1",
            fingerprint = "A29F 67B1",
            isThisDevice = true,
            admittedByLabel = "genesis (recovery key)",
            admittedLabel = "1 Sep 2026",
            expiresLabel = "renews by 30 Nov 2026",
        ),
        MemberDevice(
            id = "ed25519:5c1e88d4000000000000000000000000000000000000000000000000000000b2",
            fingerprint = "5C1E 88D4",
            isThisDevice = false,
            admittedByLabel = "A29F 67B1",
            admittedLabel = "2 Sep 2026",
            expiresLabel = "renews by 1 Dec 2026",
        ),
    )

    val pairSession = PairSession(
        thisDeviceName = "Jaryl's Nothing Phone",
        peerDeviceName = "Cove Tablet",
        securityCode = "482 7316",
    )
}
