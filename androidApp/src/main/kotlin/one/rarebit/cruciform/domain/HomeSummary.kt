package one.rarebit.cruciform.domain

/**
 * What Home leads with: one plain-language verdict over the identity's state, and the
 * few things that need the person, most pressing first. Home shows only these; the
 * fingerprints, key backing and membership dates behind them live in Manage.
 *
 * Nothing here is new state: each item restates a flag [IdentityState.Active] already
 * carries, so Home can never say "ready" while Manage says otherwise.
 */
data class HomeSummary(val status: Status, val attention: List<Attention>) {
    enum class Status {
        /** Nothing needs the person: scanning or a push signs in. */
        READY,

        /** Sign-in still works, but something should be done soon. */
        NEEDS_ATTENTION,

        /** This device is no longer a member, so it cannot sign in until re-admitted. */
        CANNOT_SIGN_IN,
    }

    /** One thing that needs the person, in the order Home shows them. */
    enum class Attention {
        /** The device's membership lapsed (or it was removed). */
        DEVICE_LAPSED,

        /** Inside the renewal window: renew while the device can still renew itself. */
        RENEW_DEVICE,

        /** The recovery secret written at creation has not been checked back yet. */
        CHECK_BACKUP,

        /** The signing key is held in software: this phone has no secure element for it. */
        SOFTWARE_KEY,
    }

    companion object {
        fun of(state: IdentityState.Active): HomeSummary {
            val attention = buildList {
                if (state.membership.lapsed) {
                    add(Attention.DEVICE_LAPSED)
                } else if (state.membership.renewalDue) {
                    add(Attention.RENEW_DEVICE)
                }
                if (state.backup.confirmPending) add(Attention.CHECK_BACKUP)
                if (!state.device.hardwareBacked) add(Attention.SOFTWARE_KEY)
            }
            val status = when {
                Attention.DEVICE_LAPSED in attention -> Status.CANNOT_SIGN_IN
                attention.isNotEmpty() -> Status.NEEDS_ATTENTION
                else -> Status.READY
            }
            return HomeSummary(status, attention)
        }
    }
}
