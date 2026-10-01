package one.rarebit.cruciform.platform

import android.content.Context

/**
 * Persisted push-plane choice (Settings → "Push plane"), the notify twin of
 * [RelaySettings]. Plain SharedPreferences: the plane's URL is public
 * configuration, not a secret.
 *
 * [current] is read AT REGISTRATION TIME (a provider lambda, not a value captured
 * at app start), so pointing the app at a different plane in Settings takes effect
 * on the next app open — the moment the app re-registers its wake endpoint —
 * without recreating the engine or restarting the app.
 */
class NotifySettings(context: Context) : EndpointSetting {

    private val prefs = context.getSharedPreferences("void-which-binds.notify", Context.MODE_PRIVATE)

    /** The configured plane base, or [NotifyConfig.DEFAULT_NOTIFY] when none is set. */
    override fun current(): String = stored() ?: NotifyConfig.DEFAULT_NOTIFY

    private fun stored(): String? = prefs.getString(KEY_NOTIFY, null)?.takeIf { it.isNotBlank() }

    /** True when no override is stored (the default is in effect). */
    override fun isDefault(): Boolean = !prefs.contains(KEY_NOTIFY)

    /**
     * Validate and persist. Returns the [RelayConfig.Validation] so the caller can show
     * the reason inline; nothing is written on `Invalid`.
     */
    override fun set(input: String): RelayConfig.Validation {
        val v = NotifyConfig.validate(input)
        if (v is RelayConfig.Validation.Valid) prefs.edit().putString(KEY_NOTIFY, v.url).apply()
        return v
    }

    /** Drop the override: [current] returns the default again. */
    override fun reset() {
        prefs.edit().remove(KEY_NOTIFY).apply()
    }

    private companion object {
        const val KEY_NOTIFY = "notify_base"
    }
}
