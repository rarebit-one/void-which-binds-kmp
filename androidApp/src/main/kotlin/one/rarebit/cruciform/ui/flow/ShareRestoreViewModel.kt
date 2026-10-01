package one.rarebit.cruciform.ui.flow

import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.domain.ShareRefusals
import one.rarebit.cruciform.domain.VoidbindEngine
import one.rarebit.voidwhichbinds.RecoverySecret
import one.rarebit.voidwhichbinds.RecoveryShares

/**
 * Restoring an identity from SLIP-39 recovery shares (void-which-binds-go ADR-0011), typed one
 * at a time: each share is checked the moment it is added (a typo, a share of another
 * set, the same share twice), progress counts toward the threshold the first share
 * states, and once exactly enough are in, [restore] combines them and restores through
 * the engine's usual [VoidbindEngine.restoreIdentity] path, with the rebuilt secret in
 * its bech32m form.
 *
 * **Memory only.** The shares are secret material, so they live in this ViewModel and
 * nowhere else: no SavedStateHandle, no saved-instance Bundle. Process death forgets
 * them and the person types them again. [startOver] and [onCleared] drop them.
 */
class ShareRestoreViewModel(
    private val engine: VoidbindEngine,
    /** Where the PBKDF2-heavy combination runs; a test passes its own. */
    private val combineDispatcher: CoroutineDispatcher = Dispatchers.Default,
) : ViewModel() {

    /**
     * [given] shares accepted of the [needed] the set asks for (null until the first
     * share is in); [error] says why the last share, or the restore, was refused.
     */
    data class State(
        val given: Int = 0,
        val needed: Int? = null,
        val error: String? = null,
        val busy: Boolean = false,
    ) {
        /** Exactly enough shares to combine. */
        val complete: Boolean get() = needed != null && given == needed
    }

    private val shares = mutableListOf<String>()

    private val _state = MutableStateFlow(State())
    val state: StateFlow<State> = _state.asStateFlow()

    /**
     * Check [mnemonic] against the shares already in and add it. False, with [State.error]
     * set, when it is refused: a refused share is never kept.
     */
    fun add(mnemonic: String): Boolean {
        val text = mnemonic.trim()
        if (text.isEmpty() || _state.value.complete || _state.value.busy) return false
        val (needed, refusal) = verdict(shares + text)
        if (refusal == null) shares += text
        _state.update { it.copy(given = shares.size, needed = needed ?: it.needed, error = refusal) }
        return refusal == null
    }

    /** The threshold [candidate] states, and why it is refused (null when it is not). */
    private fun verdict(candidate: List<String>): Pair<Int?, String?> = try {
        val needed = RecoveryShares.progress(candidate).needed
        needed to (if (needed == null) ShareRefusals.MULTI_GROUP else null)
    } catch (e: IllegalArgumentException) {
        null to ShareRefusals.describe(e)
    }

    /**
     * Combine the shares and restore the identity they rebuild. True when restored: the
     * shares are then forgotten. On a refusal or an engine failure (a declined prompt,
     * say) the reason is in [State.error] and the shares stay in, so it can be retried.
     */
    suspend fun restore(): Boolean {
        val current = _state.value
        if (!current.complete || current.busy) return false
        _state.update { it.copy(busy = true, error = null) }
        val entered = shares.toList()
        val failure = try {
            val secret = withContext(combineDispatcher) { RecoverySecret.fromShares(entered) }
            when (val result = engine.restoreIdentity(secret.format())) {
                is EngineResult.Ready -> null
                is EngineResult.Failed -> result.failure.message
            }
        } catch (e: IllegalArgumentException) {
            ShareRefusals.describe(e)
        }
        if (failure == null) startOver() else _state.update { it.copy(busy = false, error = failure) }
        return failure == null
    }

    /** Forget every share entered, and the progress. */
    fun startOver() {
        shares.clear()
        _state.value = State()
    }

    override fun onCleared() {
        startOver()
    }
}
