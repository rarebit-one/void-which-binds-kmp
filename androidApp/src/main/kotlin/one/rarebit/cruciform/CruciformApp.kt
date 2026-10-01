package one.rarebit.cruciform

import android.app.Application
import one.rarebit.voidwhichbinds.VoidbindAndroid

/**
 * Provides the application [android.content.Context] to the library once, so the
 * hardware [one.rarebit.voidwhichbinds.DeviceKeyStore] can persist its sealed key. Must
 * run before any keystore use — hence `Application.onCreate`.
 */
class CruciformApp : Application() {
    override fun onCreate() {
        super.onCreate()
        VoidbindAndroid.init(this)
    }
}
