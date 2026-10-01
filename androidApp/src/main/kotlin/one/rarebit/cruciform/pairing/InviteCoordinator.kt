package one.rarebit.cruciform.pairing

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import one.rarebit.cruciform.domain.EngineFailure
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.domain.PairInviteDisplay
import one.rarebit.cruciform.domain.PairSession
import one.rarebit.cruciform.domain.VoidbindEngine
import one.rarebit.cruciform.handoff.SamePhonePairCallback

/**
 * The lifecycle of ONE pairing invite this device mints as the initiator, owned by the
 * app (a ViewModel scope), not by a screen (ADR-0007).
 *
 * Why: the initiator's relay handshake used to run in a `LaunchedEffect` on the Connect
 * screen. The moment the user switched to the relying-party app on the same phone — to
 * create its key behind a fingerprint, tens of seconds — the effect was cancelled, the
 * initiator never posted its reveal, and on return the screen either timed out or minted
 * a fresh invite (the node relay saw 6 invites in 12 minutes for one enrolment). Here the
 * handshake is a [Job] in [scope] keyed by the invite; screens OBSERVE [state] and never
 * restart it on recomposition or return, [ensureInvite] never re-mints while an invite is
 * live, and a [ProcessKeepAlive] (a foreground service on Android) holds the process
 * while we wait — up to the relay's session TTL, with a visible countdown.
 */
class InviteCoordinator(
    private val engine: VoidbindEngine,
    private val scope: CoroutineScope,
    /** The configured relay, read at mint time (Settings → "Pairing relay"). Named in a failure. */
    private val relayUrl: () -> String,
    private val clock: () -> Long = System::currentTimeMillis,
    private val keepAlive: ProcessKeepAlive = ProcessKeepAlive.None,
    private val log: (String) -> Unit = {},
) {

    /** Which step of the invite failed — it decides what Retry does. */
    enum class Phase {
        /** Minting (opening the relay session): Retry mints again. */
        MINT,

        /** Waiting for / handshaking with the new device: the session is spent, Retry mints a fresh invite. */
        WAIT,

        /** Confirming (authorise + deliver the sealed admission): Retry re-confirms the SAME session. */
        CONFIRM,
    }

    sealed interface State {
        /** No invite. The Connect screen leaves. */
        data object Idle : State

        /** Opening a relay session. */
        data object Minting : State

        /** The invite is live and the handshake job is polling the relay for the new device. */
        data class Waiting(override val invite: PairInviteDisplay, val relayUrl: String, val deadlineMillis: Long) :
            State

        /** The new device joined and the SAS is derived — show VERIFY. */
        data class Joined(override val invite: PairInviteDisplay, val session: PairSession) : State

        /** The human confirmed the SAS; the admission is being signed and delivered. */
        data class Confirming(override val invite: PairInviteDisplay, val session: PairSession) : State

        /**
         * A step failed. [invite] is kept (when there was one) so the Connect screen stays
         * put under the error dialog; [resume] is the state Retry/dismiss returns to for a
         * CONFIRM failure (the handshake is intact), null otherwise.
         */
        data class Failed(
            val failure: EngineFailure,
            val phase: Phase,
            val relayUrl: String,
            override val invite: PairInviteDisplay?,
            val resume: Joined? = null,
        ) : State

        /** The new device is admitted. Consume with [reset]. */
        data class Admitted(override val invite: PairInviteDisplay) : State

        /** The invite this state is about, when there is one. */
        val invite: PairInviteDisplay? get() = null

        /** True while an invite exists that a new device could still join or has joined. */
        val live: Boolean get() = this is Minting || this is Waiting || this is Joined || this is Confirming
    }

    /**
     * The same-phone one-tap channel (ADR-0008): what a relying-party app on THIS phone
     * has reported over `cruciform://pair-joined`, once checked against the relay.
     */
    sealed interface SamePhone {
        /** No RP on this phone has reported anything for the live invite. */
        data object None : SamePhone

        /**
         * An RP reported, and its device key + SAS agree with what the relay revealed.
         * The human is asked one question — allow this app to act as you? — behind the
         * biometric, with no code to compare. [callerPackage] is the app that fired the
         * intent, when Android told us; [rpScheme] is where to send the human back.
         */
        data class Verified(
            val report: SamePhonePairCallback.Joined,
            val rpScheme: String?,
            val callerPackage: String?,
        ) : SamePhone

        /**
         * The report disagreed with the relay reveal: the invite failed and nothing was
         * signed. Published so the RP can be told (its `<scheme>://pair-done?outcome=refused`
         * leg); it would otherwise wait on its own screen until the relay session expires.
         */
        data class Refused(val report: SamePhonePairCallback.Joined, val rpScheme: String?, val reason: String) :
            SamePhone
    }

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()

    private val _samePhone = MutableStateFlow<SamePhone>(SamePhone.None)
    val samePhone: StateFlow<SamePhone> = _samePhone.asStateFlow()

    /**
     * A report that arrived before the relay reveal did (the RP posted its commit and
     * called us back faster than our own poll came round). Held, and re-decided the
     * moment the handshake completes — never acted on early.
     */
    private var earlyReport: Pending? = null

    private data class Pending(
        val report: SamePhonePairCallback.Joined,
        val rpScheme: String?,
        val callerPackage: String?,
    )

    private var job: Job? = null

    /** A refusal still being signed/sent for the invite just declined; the next mint waits for it. */
    private var declineJob: Job? = null
    private var keptAlive = false

    /**
     * Make sure an invite is live: mints one when there is none, and does NOTHING when
     * one is already minting / waiting / joined — so "Add a device" pressed twice, a
     * return to the Connect screen, or the "Send to <app>" tap never spend a fresh
     * relay session.
     */
    fun ensureInvite() {
        val s = _state.value
        if (s.live) {
            log("ensureInvite: already ${s::class.simpleName}, not re-minting")
            return
        }
        mint()
    }

    /** Retry the failed step: MINT/WAIT mint a fresh invite; CONFIRM re-confirms the same session. */
    fun retry() {
        val s = _state.value as? State.Failed ?: return
        when (s.phase) {
            Phase.MINT, Phase.WAIT -> mint()

            Phase.CONFIRM -> {
                val resume = s.resume
                if (resume != null) {
                    _state.value = resume
                    confirm()
                } else {
                    mint()
                }
            }
        }
    }

    /** The error was dismissed: back to the intact handshake for a CONFIRM failure, else no invite. */
    fun dismissFailure() {
        val s = _state.value as? State.Failed ?: return
        _state.value = s.resume ?: State.Idle
    }

    /** The human left the flow (Back on Connect, Cancel on Verify): stop waiting, drop the invite. */
    fun cancel() {
        job?.cancel()
        job = null
        release()
        clearSamePhone()
        _state.value = State.Idle
    }

    /**
     * The human said the codes DON'T match (Verify → "No, cancel"). Tell the new device —
     * a signed refusal behind a biometric prompt (void-which-binds-go ADR-0012) — so it stops at
     * once instead of timing out, then drop the invite like [cancel]. A cancelled prompt
     * or a failed send still declines locally; only the other device's wait differs.
     * Only meaningful from [State.Joined]; otherwise it is [cancel].
     */
    fun decline() {
        val joined = _state.value as? State.Joined
        if (joined == null) {
            cancel()
            return
        }
        job?.cancel()
        job = null
        release()
        clearSamePhone()
        _state.value = State.Idle
        declineJob = scope.launch {
            when (val r = engineStep { engine.refusePairing() }) {
                is EngineResult.Ready -> log("${joined.invite.inviteId}: declined; the new device was told")
                is EngineResult.Failed -> log("${joined.invite.inviteId}: declined locally (${r.failure.kind})")
            }
        }
    }

    /** After [State.Admitted] was acted on. */
    fun reset() {
        if (_state.value is State.Admitted) {
            clearSamePhone()
            _state.value = State.Idle
        }
    }

    /**
     * A relying-party app on THIS phone reported the pairing it just joined, over the
     * local `cruciform://pair-joined` intent (ADR-0008). The report is checked against
     * what the RELAY revealed for the same session — it is never adopted:
     *
     * - agrees → [SamePhone.Verified]: the SAS comparison is settled by the two apps,
     *   and the UI asks the human ONE question behind the biometric;
     * - too early (the relay handshake has not opened the peer's commitment yet) → the
     *   report is held and re-decided when it does;
     * - a different session → ignored entirely; the live invite is untouched;
     * - disagrees → the invite FAILS loudly and nothing is ever signed. On one phone
     *   the only way to reach that is a relay substituting a key.
     *
     * [callerPackage] / [rpScheme] are what Android told us about the caller; they
     * decorate the sheet and address the return trip, and are not part of the check.
     */
    fun samePhoneJoined(
        report: SamePhonePairCallback.Joined,
        rpScheme: String? = null,
        callerPackage: String? = null,
        /**
         * The relay reveal to decide against when it is not yet published as [State.Joined]:
         * the held report is decided BEFORE the state flips, so no observer ever sees
         * Joined with [SamePhone.None] and routes through the SAS screen on the way to
         * the one-tap sheet.
         */
        against: PairSession? = null,
    ) {
        val session = _state.value.invite?.session
        val revealed =
            against ?: _state.value.let { (it as? State.Joined)?.session ?: (it as? State.Confirming)?.session }
        when (val d = SamePhonePairCallback.decide(report, session, revealed?.peerDeviceKey, revealed?.securityCode)) {
            is SamePhonePairCallback.Decision.Match -> {
                log("same-phone: ${report.session} verified against the relay (${report.dev.take(16)}…)")
                earlyReport = null
                _samePhone.value = SamePhone.Verified(report, rpScheme, callerPackage)
            }

            is SamePhonePairCallback.Decision.TooEarly -> {
                log("same-phone: ${report.session} reported before the relay reveal; holding it")
                earlyReport = Pending(report, rpScheme, callerPackage)
            }

            is SamePhonePairCallback.Decision.OtherSession -> log("same-phone: ignored — ${d.reason}")

            is SamePhonePairCallback.Decision.Mismatch -> {
                log("same-phone: REFUSED — ${d.reason}")
                earlyReport = null
                _samePhone.value = SamePhone.Refused(report, rpScheme, d.reason)
                job?.cancel()
                job = null
                release()
                _state.value = State.Failed(
                    EngineFailure(d.reason, EngineFailure.Kind.PROTOCOL, retryable = false),
                    Phase.WAIT,
                    relayUrl(),
                    _state.value.invite,
                )
            }
        }
    }

    private fun clearSamePhone() {
        earlyReport = null
        _samePhone.value = SamePhone.None
    }

    /** Seconds left before the invite's relay session expires (0 when there is no live invite). */
    fun remainingSeconds(nowMillis: Long = clock()): Int {
        val w = _state.value as? State.Waiting ?: return 0
        return ((w.deadlineMillis - nowMillis) / 1000L).toInt().coerceAtLeast(0)
    }

    /** The human matched the SAS: authorise + deliver. Only valid from [State.Joined]. */
    fun confirm() {
        val joined = _state.value as? State.Joined ?: return
        _state.value = State.Confirming(joined.invite, joined.session)
        scope.launch {
            val result = engineStep { engine.confirmPairing() }
            when (result) {
                is EngineResult.Ready -> _state.value = State.Admitted(joined.invite)

                is EngineResult.Failed -> _state.value = State.Failed(
                    result.failure,
                    Phase.CONFIRM,
                    (_state.value as? State.Waiting)?.relayUrl ?: relayUrl(),
                    joined.invite,
                    resume = joined.takeIf { result.failure.retryable },
                )
            }
        }
    }

    private fun mint() {
        job?.cancel()
        clearSamePhone()
        val relay = relayUrl()
        _state.value = State.Minting
        val pendingDecline = declineJob
        job = scope.launch {
            // The engine holds one invite at a time: let a refusal of the previous one
            // finish before a new invite replaces it, so it can never refuse the new one.
            pendingDecline?.join()
            val minted = engineStep { engine.startPairInvite() }
            val invite = when (minted) {
                is EngineResult.Failed -> {
                    _state.value = State.Failed(minted.failure, Phase.MINT, relay, invite = null)
                    return@launch
                }

                is EngineResult.Ready -> minted.value
            }
            val deadline = clock() + invite.expiresInSeconds * 1000L
            _state.value = State.Waiting(invite, relay, deadline)
            log("waiting on ${invite.inviteId} at $relay for ${invite.expiresInSeconds}s")
            hold()
            try {
                when (val hs = engineStep { engine.awaitPairHandshake() }) {
                    is EngineResult.Ready -> {
                        log("${invite.inviteId}: new device joined, SAS derived")
                        // A one-tap report that beat the relay reveal is decided now that
                        // there IS something to decide it against (ADR-0008) — and before
                        // Joined is published, so the verdict and the state land together.
                        earlyReport?.let { held ->
                            earlyReport = null
                            samePhoneJoined(held.report, held.rpScheme, held.callerPackage, against = hs.value)
                        }
                        // A mismatch above has already failed the invite; leave that standing.
                        if (_state.value !is State.Failed) _state.value = State.Joined(invite, hs.value)
                    }

                    is EngineResult.Failed -> {
                        val f = classifyWait(hs.failure, relay, deadline)
                        log("${invite.inviteId}: ${f.kind} — ${f.message}")
                        _state.value = State.Failed(f, Phase.WAIT, relay, invite)
                    }
                }
            } finally {
                release()
            }
        }
    }

    /**
     * A failure while WAITING is classified against what this session already proved:
     * the relay answered when the invite was minted, so a transport failure now is the
     * relay dropping (or this phone's network changing), NOT "can't reach" — and a
     * timeout is only genuine at the session deadline.
     */
    private fun classifyWait(f: EngineFailure, relay: String, deadlineMillis: Long): EngineFailure = when (f.kind) {
        EngineFailure.Kind.UNREACHABLE -> f.copy(
            message =
            "The relay answered when the invite was minted, but stopped answering while waiting for the new device " +
                "(${remainingText(deadlineMillis)}). Check Wi-Fi or your VPN, then start again with a fresh invite.",
        )

        EngineFailure.Kind.TIMEOUT -> {
            if (clock() < deadlineMillis - EARLY_TIMEOUT_SLACK_MILLIS) {
                // The transport gave up before the session did: report it as what it is.
                f.copy(
                    message = "Stopped waiting early (${remainingText(
                        deadlineMillis,
                    )} of the invite were left). Start again with a fresh invite.",
                )
            } else {
                f.copy(
                    message = "The other device didn't join before the invite expired. Start again with a fresh invite.",
                )
            }
        }

        else -> f
    }

    private fun remainingText(deadlineMillis: Long): String {
        val s = ((deadlineMillis - clock()) / 1000L).coerceAtLeast(0)
        return "${s / 60}m ${s % 60}s"
    }

    private fun hold() {
        if (keptAlive) return
        keptAlive = true
        runCatching { keepAlive.begin() }.onFailure { log("keepAlive.begin failed: ${it.message}") }
    }

    private fun release() {
        if (!keptAlive) return
        keptAlive = false
        runCatching { keepAlive.end() }.onFailure { log("keepAlive.end failed: ${it.message}") }
    }

    /**
     * Run an engine step. The engine returns a value for every transport/hardware
     * failure; this is the final guard for anything unexpected — but a cancellation is
     * NOT a failure and must propagate, or a cancelled job would publish a stale state.
     */
    private inline fun <T> engineStep(block: () -> EngineResult<T>): EngineResult<T> = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (t: Throwable) {
        EngineResult.Failed(
            EngineFailure(
                message = if (t is IllegalArgumentException ||
                    t is IllegalStateException
                ) {
                    t.message ?: "Couldn't complete the pairing."
                } else {
                    "Couldn't complete the pairing."
                },
                kind = EngineFailure.Kind.INTERNAL,
                retryable = false,
            ),
        )
    }

    companion object {
        /** A TIMEOUT this far before the deadline is the transport giving up, not the session expiring. */
        const val EARLY_TIMEOUT_SLACK_MILLIS = 15_000L
    }
}
