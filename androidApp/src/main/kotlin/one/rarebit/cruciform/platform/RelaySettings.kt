package one.rarebit.cruciform.platform

import android.content.Context

/**
 * Persisted pairing-relay choice (Settings → "Pairing relay"). Plain SharedPreferences:
 * the relay URL is public configuration, not a secret. [current] is read by the
 * engine AT INVITE TIME (a provider lambda, not a value captured at app start), so a
 * change in Settings takes effect on the next "Add a device" without a restart.
 *
 * Only the initiator side consults this: a device JOINING an invite pairs through
 * the relay named in the scanned invite, never through this setting.
 */
class RelaySettings(context: Context) : EndpointSetting {

    private val prefs = context.getSharedPreferences("void-which-binds.relay", Context.MODE_PRIVATE)

    /** The configured relay base, or [RelayConfig.DEFAULT_RELAY] when none is set. */
    override fun current(): String = stored() ?: RelayConfig.DEFAULT_RELAY

    private fun stored(): String? = prefs.getString(KEY_RELAY, null)?.takeIf { it.isNotBlank() }

    /** True when no override is stored (the default is in effect). */
    override fun isDefault(): Boolean = !prefs.contains(KEY_RELAY)

    /**
     * Validate and persist. Returns the [RelayConfig.Validation] so the caller can show
     * the reason inline; nothing is written on `Invalid`.
     */
    override fun set(input: String): RelayConfig.Validation {
        val v = RelayConfig.validate(input)
        if (v is RelayConfig.Validation.Valid) prefs.edit().putString(KEY_RELAY, v.url).apply()
        return v
    }

    /** Drop the override: [current] returns the default again. */
    override fun reset() {
        prefs.edit().remove(KEY_RELAY).apply()
    }

    private companion object {
        const val KEY_RELAY = "relay_base"
    }
}
