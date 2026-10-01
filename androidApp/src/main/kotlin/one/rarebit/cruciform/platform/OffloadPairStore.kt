package one.rarebit.cruciform.platform

import android.content.Context
import one.rarebit.voidbind.crypto.Hex

/** The public desktop identity Cruciform trusts for offload requests. */
data class OffloadPair(val relayBase: String, val transportSigningKey: ByteArray) {
    override fun equals(other: Any?): Boolean = other is OffloadPair &&
        relayBase == other.relayBase && transportSigningKey.contentEquals(other.transportSigningKey)

    override fun hashCode(): Int = 31 * relayBase.hashCode() + transportSigningKey.contentHashCode()
}

/**
 * Persists the paired desktop's public transport key and relay. No private or
 * encryption key belongs here: Cruciform keeps the device X25519 secret in its
 * existing hardware-sealed identity store.
 */
class OffloadPairStore(context: Context) {
    private val prefs = context.getSharedPreferences("voidbind.offload", Context.MODE_PRIVATE)

    fun all(): List<OffloadPair> = prefs.all.mapNotNull { (key, value) ->
        if (!key.startsWith(PAIR_PREFIX)) return@mapNotNull null
        val publicKey = runCatching { Hex.decode(key.removePrefix(PAIR_PREFIX)) }.getOrNull() ?: return@mapNotNull null
        val relay = value as? String ?: return@mapNotNull null
        if (relay.isBlank() || publicKey.size != ED25519_KEY_SIZE) return@mapNotNull null
        OffloadPair(relay, publicKey)
    }

    fun save(pair: OffloadPair) {
        require(pair.transportSigningKey.size == 32) { "desktop transport key must be Ed25519" }
        prefs.edit()
            .putString(PAIR_PREFIX + Hex.encode(pair.transportSigningKey), pair.relayBase)
            .apply()
    }

    fun remove(pair: OffloadPair) {
        prefs.edit().remove(PAIR_PREFIX + Hex.encode(pair.transportSigningKey)).apply()
    }

    fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val PAIR_PREFIX = "desktop."
        const val ED25519_KEY_SIZE = 32
    }
}
