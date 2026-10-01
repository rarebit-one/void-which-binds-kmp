package one.rarebit.cruciform.domain

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import one.rarebit.cruciform.platform.BiometricAuthenticator
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.platform.OffloadPair
import one.rarebit.cruciform.platform.OffloadPairStore
import one.rarebit.cruciform.platform.StrongAuth
import one.rarebit.voidbind.Ed25519Signer
import one.rarebit.voidbind.Ed25519Verifier
import one.rarebit.voidbind.crypto.Hex
import one.rarebit.voidbind.crypto.VoidbindEncryption
import one.rarebit.voidbind.net.RelayClient
import one.rarebit.voidbind.offload.OffloadDeepLink
import one.rarebit.voidbind.offload.OffloadPairingResponder
import one.rarebit.voidbind.offload.OffloadProtocol
import one.rarebit.voidbind.offload.OffloadSlots
import one.rarebit.voidbind.offload.OffloadTransport

/** App orchestration for the wire-level offload responder in commonMain. */
class OffloadCoordinator(
    private val identityStore: IdentityStore,
    private val pairStore: OffloadPairStore,
    private val deviceKeys: DeviceKeys,
    private val biometric: BiometricAuthenticator,
    private val transport: one.rarebit.voidbind.net.HttpTransport,
) : ViewModel() {
    sealed interface State {
        data object Idle : State
        data object Connecting : State
        data class CompareCode(val code: String) : State
        data class UnwrapApproval(val desktop: String) : State
        data class Working(val message: String) : State
        data class Complete(val message: String) : State
        data class Failed(val message: String) : State
    }

    private data class PendingPair(
        val invite: OffloadDeepLink.PairInvite,
        val relay: RelayClient,
        val responder: OffloadPairingResponder,
        val handshaken: OffloadPairingResponder.Handshaken,
    )

    private data class PendingUnwrap(
        val relay: RelayClient,
        val request: OffloadProtocol.Request,
    )

    private val _state = MutableStateFlow<State>(State.Idle)
    val state: StateFlow<State> = _state.asStateFlow()
    private var pendingPair: PendingPair? = null
    private var pendingUnwrap: PendingUnwrap? = null

    fun pair(rawInvite: String) {
        pendingPair = null
        pendingUnwrap = null
        _state.value = State.Connecting
        viewModelScope.launch {
            runCatching {
                val invite = OffloadDeepLink.parsePairInvite(rawInvite)
                check(identityStore.isProvisioned()) { "Create or restore an identity before pairing a desktop." }
                val identity = checkNotNull(identityStore.load()) { "This phone's identity is incomplete." }
                val key = withContext(Dispatchers.IO) { deviceKeys.getOrCreate() }
                val relay = RelayClient(
                    http = transport,
                    base = invite.relayBase,
                    session = invite.session,
                    role = RelayClient.ROLE_RESPONDER,
                    maxWaitMillis = PAIR_WAIT_MILLIS,
                )
                val responder = OffloadPairingResponder(
                    deviceSigner = Ed25519Signer(key::sign),
                    devicePub = key.publicKey,
                    deviceEnc = identity.encPublicKey,
                    verifier = Ed25519Verifier.software(),
                )
                val handshaken = withContext(Dispatchers.IO) { responder.handshake(relay.asOffloadTransport(), invite) }
                pendingPair = PendingPair(invite, relay, responder, handshaken)
                _state.value = State.CompareCode(handshaken.sas)
            }.onFailure { _state.value = State.Failed(it.message ?: "Couldn't connect to the paired desktop.") }
        }
    }

    fun confirmPair() {
        val pending = pendingPair ?: return
        _state.value = State.Working("Confirming the desktop")
        viewModelScope.launch {
            runCatching {
                when (biometric.authenticateStrong("Pair Heyarr Desktop", "Confirm this paired computer")) {
                    StrongAuth.SUCCESS -> Unit
                    StrongAuth.CANCELLED -> error("Pairing was cancelled.")
                    StrongAuth.UNAVAILABLE -> error("A strong biometric is required to pair a desktop.")
                }
                withContext(Dispatchers.IO) {
                    pending.responder.confirm(pending.relay.asOffloadTransport(), pending.invite, pending.handshaken)
                }
                pairStore.save(OffloadPair(pending.invite.relayBase, pending.handshaken.transportPub))
                pendingPair = null
                _state.value = State.Complete("Heyarr Desktop is paired with this phone.")
            }.onFailure { _state.value = State.Failed(it.message ?: "Couldn't confirm the desktop pairing.") }
        }
    }

    fun receiveWake(rawWake: String) {
        pendingPair = null
        pendingUnwrap = null
        _state.value = State.Connecting
        viewModelScope.launch {
            runCatching {
                val wake = OffloadDeepLink.parseWakePing(rawWake)
                val pairs = pairStore.all().filter { it.relayBase.trimEnd('/') == wake.relayBase.trimEnd('/') }
                require(pairs.isNotEmpty()) { "Pair this phone with Heyarr Desktop first." }
                val relay = RelayClient(
                    http = transport,
                    base = wake.relayBase,
                    session = wake.session,
                    role = RelayClient.ROLE_RESPONDER,
                    maxWaitMillis = UNWRAP_WAIT_MILLIS,
                )
                val requestBytes = withContext(Dispatchers.IO) { relay.fetch(OffloadSlots.UNWRAP_REQ) }
                val verifier = Ed25519Verifier.software()
                val matched = pairs.firstNotNullOfOrNull { candidate ->
                    runCatching {
                        candidate to OffloadProtocol.verifyRequest(verifier, candidate.transportSigningKey, requestBytes)
                    }.getOrNull()
                } ?: error("The unwrap request is not signed by a paired desktop.")
                pendingUnwrap = PendingUnwrap(relay, matched.second)
                val desktopFingerprint = Hex.encode(matched.first.transportSigningKey).takeLast(8)
                _state.value = State.UnwrapApproval("Heyarr Desktop · $desktopFingerprint")
            }.onFailure { _state.value = State.Failed(it.message ?: "Couldn't verify this desktop request.") }
        }
    }

    fun approveUnwrap() {
        val pending = pendingUnwrap ?: return
        _state.value = State.Working("Unlocking the space key")
        viewModelScope.launch {
            runCatching {
                when (biometric.authenticateStrong("Unlock Heyarr space", "Allow this desktop to open its encrypted space")) {
                    StrongAuth.SUCCESS -> Unit
                    StrongAuth.CANCELLED -> error("The unwrap request was denied.")
                    StrongAuth.UNAVAILABLE -> error("A strong biometric is required to unlock this space.")
                }
                val seed = withContext(Dispatchers.IO) {
                    checkNotNull(identityStore.encPrivateKey()) { "This phone's encryption key is unavailable." }
                }
                try {
                    withContext(Dispatchers.IO) {
                        val key = VoidbindEncryption.unwrap(pending.request.wrapped, seed)
                        try {
                            val sealed = VoidbindEncryption.seal(key, pending.request.ephPub)
                            val signer = Ed25519Signer { message -> deviceKeys.getOrCreate().sign(message) }
                            val reply = OffloadProtocol.signResponse(signer, pending.request.nonce, sealed)
                            pending.relay.post(OffloadSlots.UNWRAP_RESP, reply)
                        } finally {
                            key.fill(0)
                        }
                    }
                } finally {
                    seed.fill(0)
                }
                pendingUnwrap = null
                _state.value = State.Complete("The phone approved the space-key request.")
            }.onFailure { _state.value = State.Failed(it.message ?: "Couldn't complete the space-key request.") }
        }
    }

    fun deny() {
        pendingPair = null
        pendingUnwrap = null
        _state.value = State.Idle
    }

    private fun RelayClient.asOffloadTransport(): OffloadTransport = object : OffloadTransport {
        override fun post(type: String, payload: ByteArray) = this@asOffloadTransport.post(type, payload)
        override fun fetch(type: String): ByteArray = this@asOffloadTransport.fetch(type)
    }

    private companion object {
        const val PAIR_WAIT_MILLIS = 10 * 60 * 1000L
        const val UNWRAP_WAIT_MILLIS = 2 * 60 * 1000L
    }
}
