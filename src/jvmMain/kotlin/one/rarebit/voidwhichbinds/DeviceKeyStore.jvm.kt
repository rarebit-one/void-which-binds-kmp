package one.rarebit.voidwhichbinds

import java.util.concurrent.ConcurrentHashMap

/**
 * JVM `actual` for [DeviceKeyStore]. **Software key — NOT hardware-backed.**
 *
 * Dev/test and desktop only. It generates an in-heap Ed25519 key per alias
 * (via the shared [Ed25519Engine], the same software engine the hardware targets
 * use after unsealing) and caches it for the process lifetime, so the pure domain
 * is testable end to end. There is no secure element on a plain JVM, so
 * [isHardwareBacked] is always `false` and the seed is never sealed.
 */
actual class DeviceKeyStore private constructor(private val seed: ByteArray, private val publicKey: ByteArray) {

    actual val isHardwareBacked: Boolean = false

    actual fun publicKey(): KeyRef = KeyRef.ed25519(publicKey)

    actual fun sign(message: ByteArray): ByteArray = Ed25519Engine.sign(seed, message)

    actual companion object {
        private val store = ConcurrentHashMap<String, DeviceKeyStore>()

        /**
         * [userAuthValiditySeconds] is accepted for source compatibility with the hardware
         * targets but **ignored**: a plain JVM has no secure element and no user-presence gate,
         * so there is no authentication window to bind. Software key, dev/test only.
         */
        actual fun getOrCreate(alias: String, userAuthValiditySeconds: Int): DeviceKeyStore = store.getOrPut(alias) {
            val g = Ed25519Engine.generate()
            DeviceKeyStore(g.privateSeed, g.publicKey)
        }
    }
}
