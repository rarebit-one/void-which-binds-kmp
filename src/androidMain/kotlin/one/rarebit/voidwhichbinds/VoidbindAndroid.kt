package one.rarebit.voidwhichbinds

import android.content.Context

/**
 * Android needs an application [Context] to persist the sealed device key, which
 * the common `DeviceKeyStore.getOrCreate(alias)` contract does not carry. The app
 * calls [init] once (e.g. in `Application.onCreate`) before using the store.
 */
object VoidbindAndroid {

    @Volatile
    private var appContext: Context? = null

    /** Provide the application context. Idempotent; keeps the application context only. */
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    internal fun requireContext(): Context = appContext ?: throw DeviceKeyStoreException(
        "VoidbindAndroid.init(context) must be called before using DeviceKeyStore on Android",
    )
}
