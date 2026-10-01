package one.rarebit.cruciform.platform.push

import android.content.Context
import android.content.Intent
import java.util.UUID

/**
 * The **registration** half of UnifiedPush — the piece [UnifiedPushReceiver] was
 * missing. The receiver handles the distributor's answers (`NEW_ENDPOINT`, `MESSAGE`,
 * …); this asks a distributor for an endpoint in the first place.
 *
 * Hand-rolled against the UnifiedPush **distributor broadcast contract**, to match the
 * dependency-free receiver: a distributor (e.g. ntfy) declares a receiver for
 * [ACTION_REGISTER]; we discover those, pick one, persist the choice + a stable
 * instance token, and broadcast `REGISTER {token, application}` to it. The distributor
 * mints a topic on its configured server and broadcasts `NEW_ENDPOINT {token, endpoint}`
 * back to us — which [UnifiedPushReceiver] stores, and the app registers with the notify
 * plane. Without this call, no endpoint is ever obtained and there is no background wake.
 *
 * Idempotent: a re-registration with the same token yields the same endpoint, so it is
 * safe to call on every app open (and cheap — one broadcast).
 */
object UnifiedPushRegistrar {

    /** Distributor-side contract (the connector broadcasts these AT a distributor). */
    const val ACTION_REGISTER = "org.unifiedpush.android.distributor.REGISTER"
    const val ACTION_UNREGISTER = "org.unifiedpush.android.distributor.UNREGISTER"
    const val EXTRA_TOKEN = "token"
    const val EXTRA_APPLICATION = "application"

    private const val PREFS = "void-which-binds.push"
    private const val KEY_DISTRIBUTOR = "distributor"
    private const val KEY_TOKEN = "token"

    /** Installed distributors: packages that declare a receiver for [ACTION_REGISTER]. */
    fun distributors(context: Context): List<String> = context.packageManager
        .queryBroadcastReceivers(Intent(ACTION_REGISTER), 0)
        .mapNotNull { it.activityInfo?.packageName }
        .distinct()

    /**
     * Ask a distributor for a wake endpoint. Returns the chosen distributor package, or
     * null when none is installed (then the app has no background wake and login falls
     * back to a scanned QR — the same graceful degradation the receiver documents).
     *
     * Picks a previously-saved distributor when it is still installed, else the first
     * available (auto-select the sole one). A stable [instance] separates registrations;
     * the default single instance is enough for one wake channel.
     */
    fun register(context: Context, instance: String = ""): String? {
        val app = context.applicationContext
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val available = distributors(app)
        if (available.isEmpty()) return null

        val chosen = prefs.getString(KEY_DISTRIBUTOR, null)?.takeIf { it in available }
            ?: available.first().also { prefs.edit().putString(KEY_DISTRIBUTOR, it).apply() }

        val token = prefs.getString(tokenKey(instance), null)
            ?: UUID.randomUUID().toString().also { prefs.edit().putString(tokenKey(instance), it).apply() }

        app.sendBroadcast(
            Intent(ACTION_REGISTER).apply {
                setPackage(chosen)
                putExtra(EXTRA_TOKEN, token)
                putExtra(EXTRA_APPLICATION, app.packageName)
            },
        )
        return chosen
    }

    /** Tell the distributor to drop this registration (best-effort). */
    fun unregister(context: Context, instance: String = "") {
        val app = context.applicationContext
        val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val distributor = prefs.getString(KEY_DISTRIBUTOR, null) ?: return
        val token = prefs.getString(tokenKey(instance), null) ?: return
        app.sendBroadcast(
            Intent(ACTION_UNREGISTER).apply {
                setPackage(distributor)
                putExtra(EXTRA_TOKEN, token)
            },
        )
    }

    private fun tokenKey(instance: String) = if (instance.isEmpty()) KEY_TOKEN else "$KEY_TOKEN.$instance"
}
