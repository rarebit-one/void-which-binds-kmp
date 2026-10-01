package one.rarebit.cruciform.testing

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import one.rarebit.cruciform.domain.ApprovalActivity
import one.rarebit.cruciform.domain.EngineFailure
import one.rarebit.cruciform.domain.EngineFailure.Kind
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.domain.IdentityState
import one.rarebit.cruciform.domain.LoginRequest
import one.rarebit.cruciform.domain.MemberDevice
import one.rarebit.cruciform.domain.PairInviteDisplay
import one.rarebit.cruciform.domain.PairSession
import one.rarebit.cruciform.domain.RecoveryBackup
import one.rarebit.cruciform.domain.RecoveryCheck
import one.rarebit.cruciform.domain.ScannedCode
import one.rarebit.cruciform.domain.SitePolicyView
import one.rarebit.cruciform.domain.VoidbindEngine
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy

/**
 * A [VoidbindEngine] whose every answer is a settable field, and which records every
 * call by name — for driving the flow ViewModels without the device engine.
 */
class ScriptedEngine : VoidbindEngine {
    val calls = mutableListOf<String>()

    var createResult: EngineResult<RecoveryBackup> = EngineResult.Ready(BACKUP)
    var restoreResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var revealResult: EngineResult<RecoveryBackup> = EngineResult.Ready(BACKUP)
    var splitResult: EngineResult<List<String>> = EngineResult.Ready(SHARES)
    var fetchResult: EngineResult<LoginRequest> = EngineResult.Ready(REQUEST)
    var approveResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var joinResult: EngineResult<PairSession> = EngineResult.Ready(SESSION)
    var confirmResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var devicesResult: EngineResult<List<MemberDevice>> = EngineResult.Ready(emptyList())
    var removeResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var renewResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var verifyResult: EngineResult<RecoveryCheck> = EngineResult.Ready(RecoveryCheck("PYJI XGNZ K7ZH XHEJ"))
    var forgetResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var settingsResult: EngineResult<Unit> = EngineResult.Ready(Unit)
    var activityResult: EngineResult<List<ApprovalActivity>> = EngineResult.Ready(emptyList())
    var policyResult: EngineResult<SitePolicyView> =
        EngineResult.Ready(SitePolicyView("rp.example.test", ApprovalPolicy.AlwaysAsk, pinnedAlwaysAsk = false))

    override val identity: StateFlow<IdentityState> = MutableStateFlow(IdentityState.None)

    /** The secret the last [restoreIdentity] was given. */
    var restoredSecret: String? = null

    private fun <T> r(name: String, result: T): T {
        calls += name
        return result
    }

    override suspend fun refresh(): EngineResult<Unit> = r("refresh", EngineResult.Ready(Unit))
    override suspend fun createIdentity() = r("createIdentity", createResult)
    override suspend fun restoreIdentity(recoverySecret: String): EngineResult<Unit> {
        restoredSecret = recoverySecret
        return r("restoreIdentity", restoreResult)
    }

    override suspend fun revealRecoverySecret() = r("revealRecoverySecret", revealResult)
    override suspend fun splitRecoverySecret() = r("splitRecoverySecret", splitResult)

    // Mirrors the real parser's shape closely enough for the flows: login / pair / other.
    override fun parseScanned(raw: String): ScannedCode = when {
        raw.startsWith("void-which-binds:login") -> ScannedCode.WebLogin("https://rp.example.test", "L1", raw)
        raw.startsWith("void-which-binds:pair") -> ScannedCode.PairInvite("https://relay.example.test", "s1", raw)
        raw.lowercase().startsWith("void-which-binds1") -> ScannedCode.RecoverySecret(raw)
        raw.lowercase().startsWith("heyarr1") -> ScannedCode.RetiredRecoverySecret(raw)
        else -> ScannedCode.Unknown(raw)
    }

    override suspend fun fetchLoginRequest(code: ScannedCode.WebLogin) = r("fetchLoginRequest", fetchResult)
    override suspend fun approveLogin(code: ScannedCode.WebLogin) = r("approveLogin", approveResult)
    override suspend fun approveNumberMatch(code: ScannedCode.WebLogin, n: Int) = r("match:$n", approveResult)
    override suspend fun denyLogin() = r("denyLogin", EngineResult.Ready(Unit))
    override suspend fun registerForPush(endpoint: String) = r("registerForPush", EngineResult.Ready(Unit))
    override suspend fun unregisterFromPush() = r("unregisterFromPush", EngineResult.Ready(Unit))
    override suspend fun startPairInvite(): EngineResult<PairInviteDisplay> = r("startPairInvite", UNUSED)
    override suspend fun awaitPairHandshake(): EngineResult<PairSession> = r("awaitPairHandshake", UNUSED)
    override suspend fun joinPairInvite(code: ScannedCode.PairInvite) = r("joinPairInvite:${code.raw}", joinResult)
    override suspend fun confirmPairing() = r("confirmPairing", confirmResult)
    override suspend fun refusePairing() = r("refusePairing", EngineResult.Ready(Unit))
    override suspend fun devices() = r("devices", devicesResult)
    override suspend fun removeDevice(deviceId: String) = r("removeDevice:$deviceId", removeResult)
    override suspend fun renewMembership() = r("renewMembership", renewResult)
    override suspend fun verifyRecoverySecret(secret: String) = r("verifyRecoverySecret", verifyResult)
    override suspend fun confirmBackup() = r("confirmBackup", EngineResult.Ready(Unit))
    override suspend fun forgetRecoverySecret() = r("forgetRecoverySecret", forgetResult)
    override suspend fun renameDevice(name: String) = r("renameDevice", settingsResult)
    override suspend fun setBiometricApproval(enabled: Boolean) = r("setBiometricApproval:$enabled", settingsResult)
    override suspend fun revokeSite(siteId: String) = r("revokeSite:$siteId", settingsResult)
    override suspend fun sitePolicy(rp: String) = r("sitePolicy", policyResult)
    override suspend fun setAlwaysAsk(rp: String, alwaysAsk: Boolean) = r("setAlwaysAsk:$alwaysAsk", settingsResult)
    override suspend fun approvalActivity(limit: Int) = r("approvalActivity", activityResult)

    companion object {
        val BACKUP = RecoveryBackup(
            groupedSecret = "void -whi ch-b inds 1qqq syqc yq5r qwzq fpg9 scrg wpug pzys nzs2 3v9c cryd pk8q " +
                "arc0 stsk a6c",
            rawSecret = "void-which-binds1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0stska6c",
            fingerprint = "PYJI XGNZ K7ZH XHEJ",
            userId = "ed25519:00",
        )
        val SHARES = listOf("share one words", "share two words", "share three words")
        val REQUEST = LoginRequest(
            domain = "rp.example.test",
            appName = "",
            origin = "https://rp.example.test",
            signInAs = "Test Phone",
            expiresInSeconds = 60,
            access = "Authentication only",
            signatureValid = true,
        )
        val SESSION = PairSession("Test Phone", peerDeviceName = "New device", securityCode = "123 4567")
        private val UNUSED = EngineResult.Failed(EngineFailure("unused", Kind.INTERNAL))
        const val LOGIN = "void-which-binds:login?v=1&rp=https://rp.example.test&id=L1"
        const val INVITE = "void-which-binds:pair?v=4&relay=https://relay.example.test&session=s1"

        fun failure(kind: Kind = Kind.UNREACHABLE, msg: String = "x") = EngineResult.Failed(EngineFailure(msg, kind))
    }
}
