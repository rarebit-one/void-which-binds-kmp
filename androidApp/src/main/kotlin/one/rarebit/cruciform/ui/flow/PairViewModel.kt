package one.rarebit.cruciform.ui.flow

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import one.rarebit.cruciform.domain.EngineFailure
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.domain.PairSession
import one.rarebit.cruciform.domain.ScannedCode
import one.rarebit.cruciform.domain.VoidbindEngine

/**
 * The RESPONDER side of pairing — this phone joining another member's invite (by scan
 * or deep link) → compare the security code → confirm. (The initiator's invite lives in
 * the app-scoped [one.rarebit.cruciform.pairing.InviteCoordinator].)
 *
 * **Survives process death:** the invite being joined (the raw `void-which-binds:pair` tuple:
 * relay URL, session id, salt, identity key — all public, the same string the QR
 * shows). The handshake itself (nonces, the SAS, the encryption key it will unseal
 * with) lives only in the engine's memory and dies with the process, so it is
 * deliberately not persisted: after process death the VERIFY screen explains the
 * pairing was interrupted and its Retry re-joins the SAME invite without a rescan.
 */
class PairViewModel(private val engine: VoidbindEngine, private val saved: SavedStateHandle) : ViewModel() {

    sealed interface Event {
        /** The handshake reached a SAS: show VERIFY. [fromScan] pops the scanner first. */
        data class Verify(val fromScan: Boolean) : Event

        /** The sealed admission arrived and was stored: this device is a member. */
        data object Admitted : Event

        /** Confirming failed ([error] is set). A non-[retryable] failure ends the flow. */
        data class ConfirmFailed(val retryable: Boolean) : Event
    }

    private val _session = MutableStateFlow<PairSession?>(null)
    val session: StateFlow<PairSession?> = _session.asStateFlow()

    private val _error = MutableStateFlow<EngineErrorState?>(null)
    val error: StateFlow<EngineErrorState?> = _error.asStateFlow()

    private val events = Channel<Event>(Channel.BUFFERED)
    val eventFlow: Flow<Event> = events.receiveAsFlow()

    /** The raw invite being joined, if any (persisted). */
    val pendingInvite: StateFlow<String?> = saved.getStateFlow<String?>(KEY_INVITE, null)

    /**
     * Join [code] as the new device and run the handshake to the SAS — the one path a
     * scan, a deep link and the error dialog's Retry share, so Retry re-joins the SAME
     * invite.
     */
    fun join(code: ScannedCode.PairInvite, fromScan: Boolean) {
        saved[KEY_INVITE] = code.raw
        viewModelScope.launch {
            when (val result = engine.joinPairInvite(code)) {
                is EngineResult.Ready -> {
                    _session.value = result.value
                    events.send(Event.Verify(fromScan))
                }

                is EngineResult.Failed -> _error.value = EngineErrorState(
                    result.failure,
                    retry = retryIf(result.failure) { join(code, fromScan) },
                    onDismiss = ::dismissError,
                )
            }
        }
    }

    /** The human says the codes match: receive the sealed admission. */
    fun confirm() {
        viewModelScope.launch {
            when (val result = engine.confirmPairing()) {
                is EngineResult.Ready -> events.send(Event.Admitted)

                is EngineResult.Failed -> {
                    _error.value = EngineErrorState(
                        result.failure,
                        retry = retryIf(result.failure) { confirm() },
                        onDismiss = ::dismissError,
                    )
                    events.send(Event.ConfirmFailed(result.failure.retryable))
                }
            }
        }
    }

    /**
     * VERIFY is on screen with no handshake — the process died mid-pairing. When the
     * invite is still known, say so with a Retry that re-joins it; returns false when
     * there is nothing to resume (the caller then leaves VERIFY).
     */
    fun resumeInterrupted(): Boolean {
        val code = pendingInvite.value?.let { engine.parseScanned(it) } as? ScannedCode.PairInvite
        if (code == null) saved[KEY_INVITE] = null
        if (code != null && _session.value == null && _error.value == null) {
            _error.value = EngineErrorState(
                EngineFailure(INTERRUPTED, EngineFailure.Kind.CANCELLED, retryable = true),
                retry = {
                    dismissError()
                    join(code, fromScan = false)
                },
                onDismiss = {
                    dismissError()
                    finish()
                },
            )
        }
        return _session.value != null || code != null
    }

    private fun retryIf(failure: EngineFailure, step: () -> Unit): (() -> Unit)? {
        if (!failure.retryable) return null
        return {
            dismissError()
            step()
        }
    }

    fun dismissError() {
        _error.value = null
    }

    /**
     * The flow is over: forget the persisted invite. The session stays in memory so a
     * VERIFY screen still on screen during the exit transition keeps rendering.
     */
    fun finish() {
        saved[KEY_INVITE] = null
    }

    companion object {
        const val KEY_INVITE = "pair.invite"
        const val INTERRUPTED =
            "The pairing was interrupted when Cruciform was closed. Retry to join the same invite again."
    }
}
