package one.rarebit.cruciform.platform.push

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

/**
 * Persists the current UnifiedPush wake **endpoint** (the ntfy topic URL a
 * distributor hands us via [UnifiedPushReceiver] `NEW_ENDPOINT`). The endpoint is a
 * public address, not a secret, so plain SharedPreferences is enough; the app reads
 * it on open and (re-)registers it with the notify plane, cert-authenticated, via
 * `VoidbindEngine.registerForPush`.
 */
class PushEndpointStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun save(endpoint: String) = prefs.edit().putString(KEY, endpoint).apply()

    fun current(): String? = prefs.getString(KEY, null)

    fun clear() = prefs.edit().remove(KEY).apply()

    /**
     * The endpoint over time: the current value now, then again whenever it changes.
     * Lets the app register the endpoint with the notify plane the moment a fresh
     * `NEW_ENDPOINT` lands (the receiver writes the same prefs), not only on next open.
     */
    fun flow(): Flow<String?> = callbackFlow {
        trySend(current())
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, changed ->
            if (changed == KEY || changed == null) trySend(current())
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        awaitClose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    private companion object {
        const val FILE = "void-which-binds.push"
        const val KEY = "endpoint"
    }
}
