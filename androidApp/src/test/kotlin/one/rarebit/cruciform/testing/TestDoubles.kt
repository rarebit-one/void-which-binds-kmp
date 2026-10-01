package one.rarebit.cruciform.testing

import android.content.SharedPreferences
import one.rarebit.cruciform.domain.DeviceKeys
import one.rarebit.cruciform.domain.DeviceSigningKey
import one.rarebit.cruciform.domain.HardwareBacking
import one.rarebit.cruciform.platform.BiometricAuthenticator
import one.rarebit.cruciform.platform.SecretSealer
import one.rarebit.cruciform.platform.StrongAuth
import one.rarebit.voidwhichbinds.AuthenticationRequiredException
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException

// Plain-JVM stand-ins for the Android pieces the engine and stores touch. The unit-test
// `android.jar` is stubs only (every method throws), so nothing here calls into it: the
// interfaces are implemented directly.

/** An in-memory [SharedPreferences]; `apply()` and `commit()` both write through. */
class InMemoryPrefs : SharedPreferences {
    val values = LinkedHashMap<String, Any?>()

    override fun getAll(): Map<String, *> = HashMap(values)
    override fun getString(key: String, defValue: String?): String? = values[key] as String? ?: defValue

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defs: Set<String>?): Set<String>? = values[key] as Set<String>? ?: defs

    override fun getInt(key: String, defValue: Int): Int = values[key] as Int? ?: defValue
    override fun getLong(key: String, defValue: Long): Long = values[key] as Long? ?: defValue
    override fun getFloat(key: String, defValue: Float): Float = values[key] as Float? ?: defValue
    override fun getBoolean(key: String, defValue: Boolean): Boolean = values[key] as Boolean? ?: defValue
    override fun contains(key: String): Boolean = values.containsKey(key)
    override fun edit(): SharedPreferences.Editor = Editor()
    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener?,
    ) = Unit

    private inner class Editor : SharedPreferences.Editor {
        private val puts = LinkedHashMap<String, Any?>()
        private val removes = HashSet<String>()
        private var clear = false

        private fun stage(key: String, value: Any?): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun putString(key: String, value: String?) = stage(key, value)
        override fun putStringSet(key: String, value: Set<String>?) = stage(key, value?.toSet())
        override fun putInt(key: String, value: Int) = stage(key, value)
        override fun putLong(key: String, value: Long) = stage(key, value)
        override fun putFloat(key: String, value: Float) = stage(key, value)
        override fun putBoolean(key: String, value: Boolean) = stage(key, value)

        override fun remove(key: String): SharedPreferences.Editor {
            removes += key
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }

        override fun commit(): Boolean {
            // SharedPreferences semantics: clear() runs first, then removes, then puts.
            if (clear) values.clear()
            removes.forEach { values.remove(it) }
            puts.forEach { (k, v) -> if (v == null) values.remove(k) else values[k] = v }
            return true
        }

        override fun apply() {
            commit()
        }
    }
}

/**
 * An in-memory [SecretSealer]: "sealed" means held in a map (copies in and out).
 * [strong] records which names were sealed under the strong-biometric key.
 */
class InMemorySealer : SecretSealer {
    val secrets = HashMap<String, ByteArray>()
    val strong = HashSet<String>()

    override fun exists(name: String): Boolean = secrets.containsKey(name)
    override fun seal(name: String, secret: ByteArray) {
        secrets[name] = secret.copyOf()
    }
    override fun sealStrong(name: String, secret: ByteArray) {
        secrets[name] = secret.copyOf()
        strong += name
    }
    override fun isStrong(name: String): Boolean = name in strong
    override fun unseal(name: String): ByteArray? = secrets[name]?.copyOf()
    override fun delete(name: String) {
        secrets.remove(name)
        strong.remove(name)
    }
}

/**
 * A software device key: a real Ed25519 key (borrowed from a throwaway [UserIdentity],
 * which is the library's software Ed25519) so certs and ops it signs verify.
 * [authRequiredLoads] makes the next N [getOrCreate] calls throw like a hardware key
 * whose post-authentication window has lapsed.
 */
class SoftwareDeviceKeys(private val backing: HardwareBacking = HardwareBacking.STRONGBOX) : DeviceKeys {
    private val key = UserIdentity.create()
    var authRequiredLoads = 0
    var loads = 0
        private set

    val publicKey: ByteArray get() = key.userPublicKey

    override fun getOrCreate(): DeviceSigningKey {
        loads++
        if (authRequiredLoads > 0) {
            authRequiredLoads--
            throw AuthenticationRequiredException("auth window lapsed")
        }
        return object : DeviceSigningKey {
            override val publicKey: ByteArray get() = key.userPublicKey
            override fun sign(message: ByteArray): ByteArray = key.sign(message)
            override fun backing(): HardwareBacking = backing
        }
    }
}

/** Scripted [BiometricAuthenticator] that records every prompt title. */
class FakeBiometric(var presence: Boolean = true, var strong: StrongAuth = StrongAuth.SUCCESS) :
    BiometricAuthenticator {
    val prompts = mutableListOf<String>()

    /** When set, every prompt throws it — the caller's coroutine being torn down mid-prompt. */
    var cancelWith: CancellationException? = null

    override suspend fun authenticate(title: String, subtitle: String): Boolean {
        prompts += title
        cancelWith?.let { throw it }
        return presence
    }

    override suspend fun authenticateStrong(title: String, subtitle: String): StrongAuth {
        prompts += title
        cancelWith?.let { throw it }
        return strong
    }
}

/**
 * A scripted [HttpTransport]. By default every call fails like an unreachable host;
 * set [handler] to answer. Records every request as "METHOD url".
 */
class FakeTransport(
    var handler: (method: String, url: String, body: ByteArray?) -> HttpResponse = { _, url, _ ->
        throw IOException("unreachable: $url")
    },
) : HttpTransport {
    val requests = mutableListOf<String>()

    private fun call(method: String, url: String, body: ByteArray?): HttpResponse {
        requests += "$method $url"
        return handler(method, url, body)
    }

    override fun get(url: String): HttpResponse = call("GET", url, null)
    override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse = call("POST", url, body)
    override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse = call("PUT", url, body)
    override fun delete(url: String, body: ByteArray?, contentType: String?): HttpResponse = call("DELETE", url, body)
    override fun sleep(millis: Long) = Unit
}
