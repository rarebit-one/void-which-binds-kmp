package one.rarebit.cruciform.pairing

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.domain.ApprovalActivity
import one.rarebit.cruciform.domain.EngineFailure
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
import one.rarebit.cruciform.handoff.SamePhonePairCallback
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The invite state machine (ADR-0007), driven with a fake engine on a test dispatcher.
 * The properties that matter on the phone: ONE mint per "Add a device", never a re-mint
 * while an invite is live, the wait outlives the screen, the keep-alive is held exactly
 * for the wait, and each failure phase retries the right step.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InviteCoordinatorTest {

    private class FakeEngine : VoidbindEngine {
        var mints = 0
        var confirms = 0
        var mintResult: EngineResult<PairInviteDisplay> = EngineResult.Ready(
            PairInviteDisplay("INV · AAAA BBBB", "void-which-binds:pair?v=4&session=s1", 600, session = "s1"),
        )

        /** Completed by the test to "join" the new device (or fail the wait). */
        var handshake = CompletableDeferred<EngineResult<PairSession>>()
        var confirmResult: EngineResult<Unit> = EngineResult.Ready(Unit)

        override suspend fun startPairInvite(): EngineResult<PairInviteDisplay> {
            mints++
            return mintResult
        }
        override suspend fun awaitPairHandshake(): EngineResult<PairSession> = handshake.await()
        override suspend fun confirmPairing(): EngineResult<Unit> {
            confirms++
            return confirmResult
        }

        var refusals = 0
        var refuseResult: EngineResult<Unit> = EngineResult.Ready(Unit)

        /** When set, the refusal (biometric + send) blocks until the test completes it. */
        var refuseGate: CompletableDeferred<Unit>? = null
        override suspend fun refusePairing(): EngineResult<Unit> {
            refusals++
            refuseGate?.await()
            return refuseResult
        }

        // Unused by the coordinator.
        override val identity: StateFlow<IdentityState> = MutableStateFlow(IdentityState.Loading)
        override suspend fun refresh(): EngineResult<Unit> = EngineResult.Ready(Unit)
        override suspend fun createIdentity(): EngineResult<RecoveryBackup> = error("unused")
        override suspend fun restoreIdentity(recoverySecret: String): EngineResult<Unit> = error("unused")
        override suspend fun revealRecoverySecret(): EngineResult<RecoveryBackup> = error("unused")
        override suspend fun splitRecoverySecret(): EngineResult<List<String>> = error("unused")
        override fun parseScanned(raw: String): ScannedCode = ScannedCode.Unknown(raw)
        override suspend fun fetchLoginRequest(code: ScannedCode.WebLogin): EngineResult<LoginRequest> = error("unused")
        override suspend fun approveLogin(code: ScannedCode.WebLogin): EngineResult<Unit> = error("unused")
        override suspend fun approveNumberMatch(code: ScannedCode.WebLogin, chosen: Int): EngineResult<Unit> {
            error("unused")
        }
        override suspend fun denyLogin(): EngineResult<Unit> = error("unused")
        override suspend fun registerForPush(endpoint: String): EngineResult<Unit> = error("unused")
        override suspend fun unregisterFromPush(): EngineResult<Unit> = error("unused")
        override suspend fun joinPairInvite(code: ScannedCode.PairInvite): EngineResult<PairSession> = error("unused")
        override suspend fun devices(): EngineResult<List<MemberDevice>> = EngineResult.Ready(emptyList())
        override suspend fun removeDevice(deviceId: String): EngineResult<Unit> = EngineResult.Ready(Unit)
        override suspend fun renewMembership(): EngineResult<Unit> = EngineResult.Ready(Unit)
        override suspend fun verifyRecoverySecret(secret: String): EngineResult<RecoveryCheck> {
            val check = RecoveryCheck(fingerprint = "")
            return EngineResult.Ready(check)
        }
        override suspend fun confirmBackup(): EngineResult<Unit> = EngineResult.Ready(Unit)
        override suspend fun forgetRecoverySecret(): EngineResult<Unit> = EngineResult.Ready(Unit)
        override suspend fun renameDevice(name: String): EngineResult<Unit> = error("unused")
        override suspend fun setBiometricApproval(enabled: Boolean): EngineResult<Unit> = error("unused")
        override suspend fun revokeSite(siteId: String): EngineResult<Unit> = error("unused")
        override suspend fun sitePolicy(rp: String): EngineResult<SitePolicyView> = error("unused")
        override suspend fun setAlwaysAsk(rp: String, alwaysAsk: Boolean): EngineResult<Unit> = error("unused")
        override suspend fun approvalActivity(limit: Int): EngineResult<List<ApprovalActivity>> = error("unused")
    }

    private class CountingKeepAlive : ProcessKeepAlive {
        var begins = 0
        var ends = 0
        override fun begin() {
            begins++
        }
        override fun end() {
            ends++
        }
    }

    private val peerDev = "ed25519:9f1c0aa2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e"
    private val session = PairSession("Nothing A065", "New device", "123 4567", peerDeviceKey = peerDev)
    private var now = 1_000_000L

    // A test that ends with an invite still waiting (as the app does) cancels it, so the
    // wait job is not reported as a leaked coroutine.
    private fun TestScope.coordinator(engine: FakeEngine, keepAlive: CountingKeepAlive = CountingKeepAlive()) =
        InviteCoordinator(engine, this, relayUrl = { "http://relay.test/pair" }, clock = { now }, keepAlive = keepAlive)

    @Test
    fun ensureInviteMintsOnceAndWaits() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val keep = CountingKeepAlive()
        val c = coordinator(engine, keep)
        c.ensureInvite()
        assertTrue(c.state.value is InviteCoordinator.State.Minting)
        advanceUntilIdle()
        val w = c.state.value as InviteCoordinator.State.Waiting
        assertEquals(1, engine.mints)
        assertEquals(now + 600_000L, w.deadlineMillis)
        assertEquals("http://relay.test/pair", w.relayUrl)
        assertEquals(600, c.remainingSeconds(now))
        now += 90_000L
        assertEquals(510, c.remainingSeconds(now))
        assertEquals(1, keep.begins)
        assertEquals(0, keep.ends)
        c.cancel()
    }

    @Test
    fun ensureInviteNeverReMintsWhileAnInviteIsLive() = runTest(StandardTestDispatcher()) {
        // The bug: switching to the RP app and back (or tapping "Send to heyarr", or "Add a
        // device" again) used to mint a fresh invite each time — 6 in 12 minutes on the node.
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        c.ensureInvite()
        advanceUntilIdle()
        repeat(5) { c.ensureInvite() }
        advanceUntilIdle()
        assertEquals(1, engine.mints)
        assertTrue(c.state.value is InviteCoordinator.State.Waiting)
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        c.ensureInvite() // joined is live too
        assertEquals(1, engine.mints)
        assertTrue(c.state.value is InviteCoordinator.State.Joined)
    }

    @Test
    fun theWaitOutlivesTheScreenAndLandsOnJoined() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val keep = CountingKeepAlive()
        val c = coordinator(engine, keep)
        c.ensureInvite()
        advanceUntilIdle()
        // Nothing observes the state here — the equivalent of the user being in the RP app.
        now += 120_000L // the RP took two minutes to create its key
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        val j = c.state.value as InviteCoordinator.State.Joined
        assertEquals("123 4567", j.session.securityCode)
        assertEquals(1, keep.begins)
        assertEquals(1, keep.ends)
    }

    @Test
    fun cancelStopsTheWaitAndReleasesTheKeepAlive() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val keep = CountingKeepAlive()
        val c = coordinator(engine, keep)
        c.ensureInvite()
        advanceUntilIdle()
        c.cancel()
        assertTrue(c.state.value is InviteCoordinator.State.Idle)
        assertEquals(1, keep.ends)
        // A late join for the cancelled invite must not resurrect it.
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        assertTrue(c.state.value is InviteCoordinator.State.Idle)
        assertEquals(0, c.remainingSeconds())
    }

    @Test
    fun aTransportFailureWhileWaitingIsNamedAsTheRelayDroppingNotUnreachable() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(
            EngineResult.Failed(
                EngineFailure(
                    "Can't reach the relay at relay.test. Check Wi-Fi or your VPN and try again.",
                    EngineFailure.Kind.UNREACHABLE,
                ),
            ),
        )
        advanceUntilIdle()
        val f = c.state.value as InviteCoordinator.State.Failed
        assertEquals(InviteCoordinator.Phase.WAIT, f.phase)
        assertEquals(EngineFailure.Kind.UNREACHABLE, f.failure.kind)
        assertTrue(f.failure.message, "answered when the invite was minted" in f.failure.message)
        assertTrue(f.failure.message, "fresh invite" in f.failure.message)
        assertEquals("INV · AAAA BBBB", f.invite?.inviteId) // the Connect screen stays put under the dialog
        // Retry after a spent session mints a fresh invite.
        engine.handshake = CompletableDeferred()
        c.retry()
        advanceUntilIdle()
        assertEquals(2, engine.mints)
        assertTrue(c.state.value is InviteCoordinator.State.Waiting)
        c.cancel()
    }

    @Test
    fun anEarlyTimeoutIsDistinguishedFromTheSessionExpiring() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        now += 60_000L // the old 60 s transport bound
        engine.handshake.complete(EngineResult.Failed(EngineFailure("didn't join in time", EngineFailure.Kind.TIMEOUT)))
        advanceUntilIdle()
        val early = c.state.value as InviteCoordinator.State.Failed
        assertEquals(EngineFailure.Kind.TIMEOUT, early.failure.kind)
        assertTrue(early.failure.message, "Stopped waiting early" in early.failure.message)

        engine.handshake = CompletableDeferred()
        c.retry()
        advanceUntilIdle()
        now += 600_000L // the real deadline
        engine.handshake.complete(EngineResult.Failed(EngineFailure("didn't join in time", EngineFailure.Kind.TIMEOUT)))
        advanceUntilIdle()
        val expired = c.state.value as InviteCoordinator.State.Failed
        assertTrue(expired.failure.message, "before the invite expired" in expired.failure.message)
    }

    @Test
    fun confirmAdmitsAndAConfirmFailureRetriesTheSameSession() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        engine.confirmResult = EngineResult.Failed(EngineFailure("relay dropped", EngineFailure.Kind.UNREACHABLE))
        c.confirm()
        advanceUntilIdle()
        val f = c.state.value as InviteCoordinator.State.Failed
        assertEquals(InviteCoordinator.Phase.CONFIRM, f.phase)
        assertTrue(f.resume is InviteCoordinator.State.Joined)
        engine.confirmResult = EngineResult.Ready(Unit)
        c.retry()
        advanceUntilIdle()
        assertEquals(2, engine.confirms)
        assertEquals(1, engine.mints) // never re-minted
        assertTrue(c.state.value is InviteCoordinator.State.Admitted)
        c.reset()
        assertTrue(c.state.value is InviteCoordinator.State.Idle)
    }

    @Test
    fun dismissingAConfirmFailureReturnsToVerifyOtherwiseToIdle() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        engine.confirmResult =
            EngineResult.Failed(EngineFailure("cancelled", EngineFailure.Kind.CANCELLED, retryable = false))
        c.confirm()
        advanceUntilIdle()
        c.dismissFailure()
        assertTrue(c.state.value is InviteCoordinator.State.Idle) // not retryable → the flow ends

        engine.handshake = CompletableDeferred()
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        engine.confirmResult = EngineResult.Failed(EngineFailure("relay dropped", EngineFailure.Kind.UNREACHABLE))
        c.confirm()
        advanceUntilIdle()
        c.dismissFailure()
        assertTrue(c.state.value is InviteCoordinator.State.Joined) // retryable → back to VERIFY
    }

    @Test
    fun aMintFailureNamesTheRelayAndRetryMintsAgain() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val keep = CountingKeepAlive()
        engine.mintResult = EngineResult.Failed(EngineFailure("Can't reach the relay", EngineFailure.Kind.UNREACHABLE))
        val c = coordinator(engine, keep)
        c.ensureInvite()
        advanceUntilIdle()
        val f = c.state.value as InviteCoordinator.State.Failed
        assertEquals(InviteCoordinator.Phase.MINT, f.phase)
        assertEquals("http://relay.test/pair", f.relayUrl)
        assertEquals(0, keep.begins) // nothing to hold: no invite was minted
        engine.mintResult =
            EngineResult.Ready(PairInviteDisplay("INV · CCCC DDDD", "void-which-binds:pair?v=4&session=s2", 600))
        c.retry()
        advanceUntilIdle()
        assertEquals(2, engine.mints)
        assertTrue(c.state.value is InviteCoordinator.State.Waiting)
        assertFalse(c.state.value is InviteCoordinator.State.Failed)
        c.cancel()
    }

    // --- the same-phone one-tap channel (ADR-0008) --------------------------

    private fun report(session: String = "s1", dev: String = peerDev, sas: String = "1234567") =
        SamePhonePairCallback.Joined(session, dev, sas)

    @Test
    fun aMatchingSamePhoneReportSettlesTheSasComparison() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        assertTrue(c.state.value is InviteCoordinator.State.Joined)
        assertEquals(InviteCoordinator.SamePhone.None, c.samePhone.value)

        c.samePhoneJoined(report(), rpScheme = "heyarr-mobile", callerPackage = "one.rarebit.heyarr.mobile")

        val v = c.samePhone.value as InviteCoordinator.SamePhone.Verified
        assertEquals("heyarr-mobile", v.rpScheme)
        assertEquals("one.rarebit.heyarr.mobile", v.callerPackage)
        // Verified is a UI decision only: nothing is signed until confirm().
        assertEquals(0, engine.confirms)
        assertTrue(c.state.value is InviteCoordinator.State.Joined)
        c.cancel()
    }

    @Test
    fun aReportThatBeatsTheRelayIsHeldAndDecidedWhenTheRevealLands() = runTest(StandardTestDispatcher()) {
        // The RP posts its commit and calls back before our poll comes round. Nothing to
        // compare yet — hold it, and decide the moment the handshake completes.
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        c.samePhoneJoined(report(), rpScheme = "heyarr-mobile")
        assertEquals(InviteCoordinator.SamePhone.None, c.samePhone.value)
        assertTrue(c.state.value is InviteCoordinator.State.Waiting)

        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        assertTrue(c.samePhone.value is InviteCoordinator.SamePhone.Verified)
        c.cancel()
    }

    @Test
    fun aHeldReportIsDecidedBeforeJoinedIsPublished() = runTest(StandardTestDispatcher()) {
        // The nav host routes on Joined: with the verdict still None at that instant it
        // would open the SAS screen, then promote to the one-tap sheet a beat later —
        // the flash the human sees as "Pair a device" flipping back and forth.
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        c.samePhoneJoined(report(), rpScheme = "heyarr-mobile")

        var verdictWhenJoined: InviteCoordinator.SamePhone? = null
        val watcher = c.state
            .onEach {
                if (it is InviteCoordinator.State.Joined &&
                    verdictWhenJoined == null
                ) {
                    verdictWhenJoined = c.samePhone.value
                }
            }
            .launchIn(CoroutineScope(Dispatchers.Unconfined))
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        watcher.cancel()
        assertTrue(
            "Joined was observed with $verdictWhenJoined",
            verdictWhenJoined is InviteCoordinator.SamePhone.Verified,
        )
        c.cancel()
    }

    @Test
    fun aMismatchedReportFailsTheInviteAndSignsNothing() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()

        c.samePhoneJoined(report(dev = peerDev.dropLast(1) + "f"), rpScheme = "heyarr-mobile")

        val f = c.state.value as InviteCoordinator.State.Failed
        assertEquals(EngineFailure.Kind.PROTOCOL, f.failure.kind)
        assertFalse("a substituted key must never be retried against the same session", f.failure.retryable)
        // The RP is told, with Cruciform's own wording, so it stops waiting on its screen.
        val refused = c.samePhone.value as InviteCoordinator.SamePhone.Refused
        assertEquals("heyarr-mobile", refused.rpScheme)
        assertEquals(f.failure.message, refused.reason)
        assertEquals(0, engine.confirms)
    }

    @Test
    fun aReportForAnotherSessionLeavesTheLiveInviteAlone() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()

        c.samePhoneJoined(report(session = "someone-elses"), rpScheme = "heyarr-mobile")

        assertTrue(
            "a stale callback must not tear down the live invite",
            c.state.value is InviteCoordinator.State.Joined,
        )
        assertEquals(InviteCoordinator.SamePhone.None, c.samePhone.value)
        c.cancel()
    }

    @Test
    fun theOneTapVerdictIsDroppedWhenTheInviteIsCancelledOrReMinted() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        c.samePhoneJoined(report())
        assertTrue(c.samePhone.value is InviteCoordinator.SamePhone.Verified)

        c.cancel()
        assertEquals(InviteCoordinator.SamePhone.None, c.samePhone.value)

        // And a fresh invite starts with no verdict, whatever the last one decided.
        engine.handshake = CompletableDeferred()
        c.ensureInvite()
        advanceUntilIdle()
        assertEquals(InviteCoordinator.SamePhone.None, c.samePhone.value)
        c.cancel()
    }

    @Test
    fun confirmAfterAVerifiedReportRunsTheSameSigningPath() = runTest(StandardTestDispatcher()) {
        // The one-tap sheet changed the question, not the mechanism: Allow is confirm().
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        c.samePhoneJoined(report())
        c.confirm()
        advanceUntilIdle()
        assertEquals(1, engine.confirms)
        assertTrue(c.state.value is InviteCoordinator.State.Admitted)
        // The verdict survives to Admitted: the graph needs it to address the return trip.
        assertTrue(c.samePhone.value is InviteCoordinator.SamePhone.Verified)
        c.reset()
        assertEquals(InviteCoordinator.SamePhone.None, c.samePhone.value)
    }

    // --- "No, cancel": the codes differ (void-which-binds-go ADR-0012) -----------------------

    private fun TestScope.joined(engine: FakeEngine, keep: CountingKeepAlive): InviteCoordinator {
        val c = coordinator(engine, keep)
        c.ensureInvite()
        advanceUntilIdle()
        engine.handshake.complete(EngineResult.Ready(session))
        advanceUntilIdle()
        assertTrue(c.state.value is InviteCoordinator.State.Joined)
        return c
    }

    @Test
    fun declineSendsTheRefusalAndDropsTheInvite() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val keep = CountingKeepAlive()
        val c = joined(engine, keep)
        c.decline()
        assertEquals(InviteCoordinator.State.Idle, c.state.value)
        advanceUntilIdle()
        assertEquals(1, engine.refusals)
        assertEquals(0, engine.confirms)
        assertEquals(InviteCoordinator.State.Idle, c.state.value)
        assertEquals(keep.begins, keep.ends)
    }

    @Test
    fun aCancelledBiometricStillDeclinesLocally() = runTest(StandardTestDispatcher()) {
        // The engine sends nothing when the prompt is cancelled; the invite is dropped all
        // the same, and the other device just waits out its own timeout.
        val engine = FakeEngine()
        engine.refuseResult = EngineResult.Failed(EngineFailure("Cancelled.", EngineFailure.Kind.CANCELLED))
        val c = joined(engine, CountingKeepAlive())
        c.decline()
        advanceUntilIdle()
        assertEquals(1, engine.refusals)
        assertEquals(0, engine.confirms)
        assertEquals(InviteCoordinator.State.Idle, c.state.value)
    }

    @Test
    fun aFailedSendStillDeclinesLocally() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        engine.refuseResult = EngineResult.Failed(EngineFailure("No route.", EngineFailure.Kind.UNREACHABLE))
        val c = joined(engine, CountingKeepAlive())
        c.decline()
        advanceUntilIdle()
        assertEquals(InviteCoordinator.State.Idle, c.state.value)
        assertFalse(
            "a failed refusal must not surface as an invite failure",
            c.state.value is InviteCoordinator.State.Failed,
        )
    }

    @Test
    fun declineBeforeTheNewDeviceJoinedIsAPlainCancel() = runTest(StandardTestDispatcher()) {
        val engine = FakeEngine()
        val c = coordinator(engine)
        c.ensureInvite()
        advanceUntilIdle()
        c.decline()
        advanceUntilIdle()
        assertEquals(0, engine.refusals)
        assertEquals(InviteCoordinator.State.Idle, c.state.value)
    }

    @Test
    fun theNextInviteWaitsForTheRefusalOfTheLastOne() = runTest(StandardTestDispatcher()) {
        // The engine holds one invite: a new mint must not replace it while the refusal
        // (still behind the biometric) has yet to sign it.
        val engine = FakeEngine()
        val gate = CompletableDeferred<Unit>()
        engine.refuseGate = gate
        val c = joined(engine, CountingKeepAlive())
        c.decline()
        advanceUntilIdle()
        engine.handshake = CompletableDeferred()
        c.ensureInvite()
        advanceUntilIdle()
        assertEquals(1, engine.mints)
        assertTrue(c.state.value is InviteCoordinator.State.Minting)
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(2, engine.mints)
        assertTrue(c.state.value is InviteCoordinator.State.Waiting)
        c.cancel()
    }
}
