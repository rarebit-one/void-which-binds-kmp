package one.rarebit.cruciform.domain

import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.voidwhichbinds.auth.PossessionProof
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.NotifyClient

/**
 * This device's push-login wake registration with the notify plane, and the memory of
 * what the plane last accepted (kept in [store], so this holds no state of its own).
 *
 * The plane refuses a bare cert (void-which-binds-go v0.19.0, ADR-0022), so every
 * registration carries a possession proof signed by the device key, and on a phone that
 * signature may need a fresh biometric — [gate] is the engine's presence gate around it.
 * So a registration the plane accepted is not repeated on every app open: only a new
 * endpoint, a different plane, or a subscription within [RENEW_BEFORE_SECONDS] of
 * lapsing registers again. A refused registration is not remembered, so the next open
 * tries again.
 */
internal class PushWake(
    private val store: IdentityStore,
    private val transport: HttpTransport,
    private val deviceKeys: DeviceKeys,
    private val clock: () -> Long,
) {

    /** Whether [endpoint] at [plane] still has to be registered now. */
    fun needsRegistration(endpoint: String, plane: String): Boolean {
        val now = clock()
        val last = store.pushRegistration() ?: return true
        val same = last.endpoint == endpoint && last.plane == plane
        return !same || last.expiresAt - now <= RENEW_BEFORE_SECONDS
    }

    /**
     * Register [endpoint] at [plane] for the device admitted by [cert], presenting [ops],
     * unless the plane already holds it; remember what the plane accepted.
     */
    suspend fun register(
        plane: String,
        cert: String,
        endpoint: String,
        ops: List<String>,
        gate: suspend (() -> String) -> String,
    ) {
        if (!needsRegistration(endpoint, plane)) return
        val proof = gate { proof(cert) }
        val sub = NotifyClient(transport, plane).subscribe(cert, proof, endpoint, ops = ops)
        store.savePushRegistration(endpoint, plane, sub.expiresAt)
    }

    /** Drop this device's subscription at [plane], proving possession as [register] does, and forget it. */
    suspend fun unregister(plane: String, cert: String, ops: List<String>, gate: suspend (() -> String) -> String) {
        val proof = gate { proof(cert) }
        NotifyClient(transport, plane).unsubscribe(cert, proof, ops = ops)
        store.clearPushRegistration()
    }

    /** A possession proof over [cert], signed now by the hardware device key (may need presence). */
    private fun proof(cert: String): String {
        val key = deviceKeys.getOrCreate()
        return PossessionProof.mint(cert, { key.sign(it) }, clock())
    }

    companion object {
        /** Re-register a still-valid subscription once it is this close to lapsing (7 days). */
        const val RENEW_BEFORE_SECONDS = 7L * 24 * 60 * 60
    }
}
