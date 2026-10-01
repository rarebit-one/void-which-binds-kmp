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
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.domain.LoginRequest
import one.rarebit.cruciform.domain.ScannedCode
import one.rarebit.cruciform.domain.SitePolicyView
import one.rarebit.cruciform.domain.VoidbindEngine
import one.rarebit.cruciform.domain.failureOrNull
import one.rarebit.cruciform.domain.valueOrNull

/**
 * The web-login approval flow: a scanned / push-woken / deep-linked login code →
 * the RP's request → approve (v1 or number-match) or deny.
 *
 * **Survives process death:** the login code being approved (the raw `void-which-binds:login`
 * tuple — the RP's base URL and its short-lived login id, the same string the QR
 * carries). It is not a secret: approving still needs a fresh challenge from the RP
 * and a biometric-gated signature by the hardware key. If the process dies with the
 * approval sheet up, the sheet comes back and [resume] re-fetches the request (the
 * engine's in-memory pending login died with the process). The fetched request, the
 * site policy and any error are in-memory only.
 */
class LoginViewModel(private val engine: VoidbindEngine, private val saved: SavedStateHandle) : ViewModel() {

    sealed interface Event {
        /** The request is fetched: show the approval sheet. [fromScan] pops the scanner first. */
        data class Show(val fromScan: Boolean) : Event

        /** The fetch failed ([loginError] is set). [fromScan] closes the scanner. */
        data class FetchFailed(val fromScan: Boolean) : Event

        /** The human approved and the RP accepted. */
        data object Approved : Event

        /** The human declined. */
        data object Denied : Event

        /** The approval failed ([loginError] is set); a deep-link caller hears on dismiss. */
        data object ApprovalFailed : Event
    }

    private val _request = MutableStateFlow<LoginRequest?>(null)
    val request: StateFlow<LoginRequest?> = _request.asStateFlow()

    private val _policy = MutableStateFlow<SitePolicyView?>(null)
    val policy: StateFlow<SitePolicyView?> = _policy.asStateFlow()

    private val _loginError = MutableStateFlow<LoginErrorState?>(null)
    val loginError: StateFlow<LoginErrorState?> = _loginError.asStateFlow()

    private val _error = MutableStateFlow<EngineErrorState?>(null)
    val error: StateFlow<EngineErrorState?> = _error.asStateFlow()

    private val events = Channel<Event>(Channel.BUFFERED)
    val eventFlow: Flow<Event> = events.receiveAsFlow()

    /** The raw login code in flight, if any (persisted). */
    val pendingCode: StateFlow<String?> = saved.getStateFlow<String?>(KEY_CODE, null)

    private var fetching = false

    /** Start approving [code]: fetch the RP's request, then [Event.Show] or [Event.FetchFailed]. */
    fun open(code: ScannedCode.WebLogin, fromScan: Boolean) {
        saved[KEY_CODE] = code.raw
        _request.value = null
        _policy.value = null
        viewModelScope.launch { fetch(code, fromScan) }
    }

    /**
     * Re-fetch the request for the persisted code when the approval sheet is back
     * without one (after process death). No-op while a fetch is running, or when there
     * is nothing to resume.
     */
    fun resume() {
        if (_request.value != null || fetching) return
        val code = pendingCode.value?.let { engine.parseScanned(it) } as? ScannedCode.WebLogin
        if (code == null) {
            saved[KEY_CODE] = null
            return
        }
        viewModelScope.launch { fetch(code, fromScan = false) }
    }

    private suspend fun fetch(code: ScannedCode.WebLogin, fromScan: Boolean) {
        fetching = true
        try {
            when (val result = engine.fetchLoginRequest(code)) {
                is EngineResult.Ready -> {
                    _request.value = result.value
                    events.send(Event.Show(fromScan))
                }

                is EngineResult.Failed -> {
                    saved[KEY_CODE] = null
                    _loginError.value = LoginErrorState.of(result.failure)
                    events.send(Event.FetchFailed(fromScan))
                }
            }
        } finally {
            fetching = false
        }
    }

    /** A code that is not a login or a pairing invite, or any other one-line login error. */
    fun showError(message: String) {
        _loginError.value = LoginErrorState(message)
    }

    fun dismissLoginError() {
        _loginError.value = null
    }

    /**
     * Approve the login — a biometric-gated signature by the hardware key. [chosen] is
     * the number the human tapped on a number-matching (v2) login; null for a scanned
     * (v1) one.
     */
    fun approve(chosen: Int? = null) {
        viewModelScope.launch {
            val code = pendingCode.value?.let { engine.parseScanned(it) } as? ScannedCode.WebLogin
            val result = when {
                code == null -> null
                chosen == null -> engine.approveLogin(code)
                else -> engine.approveNumberMatch(code, chosen)
            }
            if (result is EngineResult.Ready) {
                events.send(Event.Approved)
            } else {
                _loginError.value = LoginErrorState(result?.failureOrNull()?.message ?: SIGN_IN_FAILED)
                events.send(Event.ApprovalFailed)
            }
        }
    }

    /** The human declined: record it (best-effort — the denial stands either way). */
    fun deny() {
        viewModelScope.launch {
            engine.denyLogin()
            events.send(Event.Denied)
        }
    }

    /** Fetch this RP's approval policy when the sheet opens (trusted / always-ask). */
    fun loadPolicy(domain: String) {
        viewModelScope.launch { _policy.value = engine.sitePolicy(domain).valueOrNull() }
    }

    fun setAlwaysAsk(domain: String, alwaysAsk: Boolean) {
        viewModelScope.launch {
            engine.setAlwaysAsk(domain, alwaysAsk).failureOrNull()?.let {
                _error.value = EngineErrorState(it, onDismiss = { _error.value = null })
            }
            _policy.value = engine.sitePolicy(domain).valueOrNull()
        }
    }

    /**
     * The flow is over (decided, or abandoned): forget the persisted code. The last
     * request stays in memory so a sheet still on screen during the exit transition
     * keeps rendering; the next [open] replaces it.
     */
    fun finish() {
        saved[KEY_CODE] = null
        _policy.value = null
    }

    companion object {
        const val KEY_CODE = "login.code"
        private const val SIGN_IN_FAILED = "Couldn't complete the sign-in."
    }
}
