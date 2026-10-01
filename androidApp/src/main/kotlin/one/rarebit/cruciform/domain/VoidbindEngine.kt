package one.rarebit.cruciform.domain

import kotlinx.coroutines.flow.StateFlow

/**
 * The app-side contract for "the brain" — everything the UI needs the identity core
 * to do. The real implementation binds these to the KMP library's commonMain flow
 * coordinators (identity derivation, pairing, web-login, recovery) + the hardware
 * [one.rarebit.voidwhichbinds.DeviceKeyStore]; a [PreviewVoidbindEngine] backs @Preview
 * and lets the whole UI run against the mockup data before the coordinators land.
 *
 * Everything cryptographic stays behind this seam: screens receive already-formatted
 * fingerprints and booleans and never see key bytes. Suspending calls are the ones
 * that touch hardware (a biometric-gated signature) or the network (relay/RP).
 *
 * **One error model.** Every suspending call returns an [EngineResult] and MUST NOT
 * throw for a failure — hardware, network, a missing precondition or a bug all resolve
 * to [EngineResult.Failed] carrying a user-facing [EngineFailure], converted on the
 * worker thread that failed. The single exception is coroutine cancellation: a
 * [kotlin.coroutines.cancellation.CancellationException] always propagates, so a
 * cancelled caller is torn down instead of running its failure branch (see
 * [suspendRunCatching]). Call sites therefore branch on the result and need no
 * try/catch of their own.
 */
interface VoidbindEngine {

    /** Current identity state; drives whether the app shows onboarding or home. */
    val identity: StateFlow<IdentityState>

    /** Load identity state from the keystore (call on start). */
    suspend fun refresh(): EngineResult<Unit>

    // --- Onboarding -----------------------------------------------------------

    /**
     * Create a brand-new identity: draw a recovery secret, derive the user key,
     * provision the hardware device key, self-sign the first enrolment cert. Returns
     * the recovery secret to display for backup. Biometric-gated.
     */
    suspend fun createIdentity(): EngineResult<RecoveryBackup>

    /**
     * Restore an identity on this device from a recovery secret string. A mistyped
     * secret is a `Failed` whose message says what was wrong with it.
     */
    suspend fun restoreIdentity(recoverySecret: String): EngineResult<Unit>

    /**
     * Re-display the recovery secret (Settings → Recovery backup). Biometric-gated: a
     * dismissed prompt is a `Failed` of kind CANCELLED.
     */
    suspend fun revealRecoverySecret(): EngineResult<RecoveryBackup>

    /**
     * Split the kept recovery secret into SLIP-39 shares (Settings → Split into shares):
     * the Void-Which-Binds profile, any 2 of 3, no passphrase (void-which-binds-go ADR-0011). Behind a
     * strong biometric, never the PIN, like [revealRecoverySecret]. The shares are for
     * one showing: the caller holds them in memory only. Splitting revokes nothing (the
     * written secret keeps working), and each call gives a fresh, unrelated set. A
     * device that keeps no copy is a `Failed` of kind NOT_YET.
     */
    suspend fun splitRecoverySecret(): EngineResult<List<String>>

    /**
     * Check a written recovery secret against this identity WITHOUT using it: parse it
     * (a typo is refused by the checksum), derive its identity, compare. Signs nothing
     * and needs no biometric — knowing the secret is the point. On a match it records
     * the check (see [BackupStatus]); a different identity's secret is a `Failed`.
     */
    suspend fun verifyRecoverySecret(secret: String): EngineResult<RecoveryCheck>

    /**
     * Record that the user confirmed the backup they just wrote down (the create flow
     * checks groups of it against the secret still on screen).
     */
    suspend fun confirmBackup(): EngineResult<Unit>

    /**
     * Remove this phone's copy of the recovery secret, behind a strong biometric. Only
     * once the written secret has been checked here and this device is a member (so it
     * renews itself and needs no genesis). Afterwards, re-admitting a device takes the
     * written secret.
     */
    suspend fun forgetRecoverySecret(): EngineResult<Unit>

    // --- Scanning -------------------------------------------------------------

    /** Parse a scanned QR string into a dispatchable [ScannedCode]. */
    fun parseScanned(raw: String): ScannedCode

    // --- Web login ------------------------------------------------------------

    /**
     * Fetch the details of a web-login request (from the RP) for the approval sheet.
     * The same call serves a scanned v1 login and a push-woken **number-matching**
     * one — the returned [LoginRequest.candidates] is non-empty for the latter, and
     * the UI shows the number grid instead of a plain Approve button.
     *
     * An unreachable RP, a TLS error, a timeout or a cleartext-blocked URL is a `Failed`
     * of kind UNREACHABLE; a stale login code (404/410) is EXPIRED, so the UI can say
     * "scan a fresh QR"; any other non-2xx is REJECTED.
     */
    suspend fun fetchLoginRequest(code: ScannedCode.WebLogin): EngineResult<LoginRequest>

    /**
     * Approve a scanned (v1) web login — sign the challenge with the hardware key.
     * Biometric-gated. The RP refusing the assertion is a `Failed`; nothing is trusted.
     */
    suspend fun approveLogin(code: ScannedCode.WebLogin): EngineResult<Unit>

    /**
     * Approve a **number-matching (v2)** login by the number the human tapped — sign
     * the challenge bound to [chosen] (biometric-gated) and submit it. Tapping a
     * decoy binds the wrong number and the RP refuses it (no login), which is the
     * anti-phishing point. [chosen] must be one of the fetched
     * [LoginRequest.candidates].
     */
    suspend fun approveNumberMatch(code: ScannedCode.WebLogin, chosen: Int): EngineResult<Unit>

    /**
     * The human declined the pending login. Records a denial in the approval audit
     * trail (nothing is signed, and trust is untouched) and clears the pending login.
     */
    suspend fun denyLogin(): EngineResult<Unit>

    // --- Push wake (self-hosted ntfy / UnifiedPush) ---------------------------

    /**
     * Register this device's [endpoint] (the ntfy topic URL a UnifiedPush distributor
     * handed us) with the notify plane, cert-authenticated, so a push login can wake
     * this phone. Call on app open with the current endpoint; a subscription is
     * short-lived by design, so re-registering is normal. `Failed` when there is no
     * identity yet, no plane is configured, or the plane refused it — best-effort: a
     * failure just means no background wake, and QR login still works.
     */
    suspend fun registerForPush(endpoint: String): EngineResult<Unit>

    /** Drop this device's wake subscription (cert-authenticated). Best-effort. */
    suspend fun unregisterFromPush(): EngineResult<Unit>

    // --- Pairing --------------------------------------------------------------
    //
    // Every pairing step touches the relay over a BLOCKING transport and MUST NOT throw
    // for a transport/IO failure: no route to the relay, connection refused, TLS, a
    // timeout, a cleartext-blocked URL, a relay refusal, a peer that never joins, or a
    // cancelled biometric prompt all resolve to [EngineResult.Failed] carrying a
    // user-facing [EngineFailure] — so the UI renders an error with a Retry instead of
    // the app dying with an uncaught main-thread exception (the on-device crash: a
    // `SocketTimeoutException` out of [joinPairInvite] with the phone on cellular).

    /** As the existing device: mint a pairing invite to display as a QR. */
    suspend fun startPairInvite(): EngineResult<PairInviteDisplay>

    /**
     * As the existing device, after [startPairInvite] rendered the invite: block
     * until the new device joins the relay, run the commit-before-reveal handshake,
     * and return the 7-digit SAS to compare. Signs nothing — the human gate on the
     * VERIFY screen precedes [confirmPairing], which authorises. Blocking (polls the
     * relay); an invite that expires unjoined is a `Failed` of kind TIMEOUT.
     */
    suspend fun awaitPairHandshake(): EngineResult<PairSession>

    /**
     * As the new device: join a scanned (or deep-linked) invite and run the handshake to
     * the SAS. Calling it again with the same [code] after a `Failed` re-joins the same
     * invite — that is what the UI's Retry does.
     */
    suspend fun joinPairInvite(code: ScannedCode.PairInvite): EngineResult<PairSession>

    /** After the human confirms the SAS matches: authorise/receive the sealed cert. */
    suspend fun confirmPairing(): EngineResult<Unit>

    /**
     * As the existing device, when the human says the numbers DON'T match: behind a
     * biometric prompt, sign a refusal with this device's key and post it, so the new
     * device stops at once instead of waiting out its timeout (void-which-binds-go ADR-0012).
     * Signs no op. A cancelled prompt is a `Failed` of kind CANCELLED and sends nothing.
     * Either way the invite is over: [confirmPairing] fails afterwards.
     */
    suspend fun refusePairing(): EngineResult<Unit>

    // --- Devices (membership, ADR-0005) ---------------------------------------

    /**
     * The identity's current device set as this device evaluates it from the ops it
     * knows (its replica) — including itself. Empty when there is no identity.
     */
    suspend fun devices(): EngineResult<List<MemberDevice>>

    /**
     * Remove [deviceId] from the identity: gated on a STRONG biometric (no device-credential
     * / PIN fallback — see [one.rarebit.cruciform.platform.PresencePolicy]), signs a `remove`
     * op with THIS device's hardware key (citing its heads), records it in the replica, and
     * pushes the ops to the relying parties this app knows (`POST /membership/{usr}`,
     * best-effort — an RP that does not serve the route yet is tolerated). Refuses
     * to remove this device itself. Never throws for a transport failure.
     */
    suspend fun removeDevice(deviceId: String): EngineResult<Unit>

    /**
     * Renew THIS device's membership now: a self re-add signed by its own key, which
     * must happen while its current add is still valid (a lapsed device can only be
     * re-admitted). The engine also renews on its own, without prompting, whenever the
     * device signs inside the renewal window; this is the explicit "Renew now".
     */
    suspend fun renewMembership(): EngineResult<Unit>

    // --- Settings actions -----------------------------------------------------

    suspend fun renameDevice(name: String): EngineResult<Unit>

    suspend fun setBiometricApproval(enabled: Boolean): EngineResult<Unit>

    suspend fun revokeSite(siteId: String): EngineResult<Unit>

    // --- Per-RP approval policy + audit ---------------------------------------

    /**
     * The current per-RP approval policy for [rp] (its host): trust-on-first-use vs.
     * always-ask, plus whether the user pinned always-ask. A brand-new RP is
     * always-ask/unpinned. Consult it to decide whether the approval sheet shows the
     * full review or a streamlined confirm — the biometric-gated signature is unchanged
     * either way.
     */
    suspend fun sitePolicy(rp: String): EngineResult<SitePolicyView>

    /**
     * Set [rp]'s policy: pinning [alwaysAsk] forces the full sheet on every login (and
     * blocks silent trust-on-first-use); clearing it trusts the site. Persisted.
     */
    suspend fun setAlwaysAsk(rp: String, alwaysAsk: Boolean): EngineResult<Unit>

    /** The approval-activity log, newest first, at most [limit] entries. */
    suspend fun approvalActivity(limit: Int = 100): EngineResult<List<ApprovalActivity>>
}

/** The per-RP policy as the approval sheet / settings shows it. */
data class SitePolicyView(
    val rp: String,
    val policy: one.rarebit.voidwhichbinds.policy.ApprovalPolicy,
    val pinnedAlwaysAsk: Boolean,
) {
    val trusted: Boolean get() = policy == one.rarebit.voidwhichbinds.policy.ApprovalPolicy.TrustedTofu
}
