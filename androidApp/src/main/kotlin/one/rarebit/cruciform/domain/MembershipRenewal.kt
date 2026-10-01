package one.rarebit.cruciform.domain

import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp

/**
 * This device's own membership over time (ADR-0005). An add lasts 90 days; a member
 * renews itself with a **self re-add** — an add of itself, signed by its own hardware
 * key, citing the replica's heads — while its current add is still valid. A lapsed
 * device's self re-add is `unauthorised` (void-which-binds-go vector
 * `self-renew-extends-membership`), so it can only be re-admitted by another member or
 * the recovery secret.
 *
 * Pure decisions over the replica; [DeviceVoidbindEngine] records and pushes the op.
 */
internal class MembershipRenewal(
    private val deviceKeys: DeviceKeys,
    private val clock: () -> Long,
    private val dateLabel: (Long) -> String,
) {
    /** How this device stands: renews-by date, inside the renewal window, or lapsed. */
    fun health(persisted: IdentityStore.Persisted, devicePub: ByteArray): MembershipHealth {
        val now = clock()
        val me = Membership.evaluate(usr(persisted), persisted.ops, now).members[KeyRef.ed25519(devicePub).render()]
            ?: return MembershipHealth(lapsed = true)
        return MembershipHealth(
            renewsByLabel = "renews by ${dateLabel(me.expiresAt)}",
            renewalDue = me.expiresAt - now <= WINDOW_SECONDS,
        )
    }

    /**
     * The signed self re-add, or null for a non-member (a self re-add would be
     * unauthorised) and, with [onlyIfDue], for a member not yet within
     * [WINDOW_SECONDS] of expiry. Signing may throw
     * [one.rarebit.voidwhichbinds.AuthenticationRequiredException] when the key's auth
     * window is shut; the caller decides whether to prompt.
     */
    fun selfRenewal(persisted: IdentityStore.Persisted, onlyIfDue: Boolean): String? {
        val ks = deviceKeys.getOrCreate()
        val self = KeyRef.ed25519(ks.publicKey).render()
        val usr = usr(persisted)
        val now = clock()
        val view = Membership.evaluate(usr, persisted.ops, now)
        val me = view.members[self]
        val due = me != null && (!onlyIfDue || me.expiresAt - now <= WINDOW_SECONDS)
        return if (!due) {
            null
        } else {
            MembershipOp.sign(
                { ks.sign(it) },
                ks.publicKey,
                usr,
                MembershipOp.Kind.ADD,
                dev = self,
                deviceEnc = KeyRef.x25519(persisted.encPublicKey).render(),
                prev = view.heads,
                issuedAt = now,
            )
        }
    }

    private fun usr(persisted: IdentityStore.Persisted): String = KeyRef.ed25519(persisted.userPublicKey).render()

    companion object {
        /**
         * Renew once the device's add has fewer than this many seconds left: 30 of its
         * 90 days, so a phone used even monthly renews long before it lapses.
         */
        const val WINDOW_SECONDS = 30L * 24 * 60 * 60
    }
}
