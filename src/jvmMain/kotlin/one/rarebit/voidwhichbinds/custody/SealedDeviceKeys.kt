package one.rarebit.voidwhichbinds.custody

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption

/**
 * A sealed-file device's keys for the library flows: an Ed25519 signer (the sealed file's
 * `device` signer) and an X25519 unwrap, with the passphrase asked for lazily on the first
 * private operation and the seeds held for [ttlMillis] after it (ADR-0010).
 *
 * The semantics are void-which-binds-go's CLI `lazyKeys` (#165): asking for a public key
 * never asks for the passphrase; a private operation unlocks if the hold has lapsed, and the
 * hold is measured from when the KDF returns. A failed **first** unlock is kept, so a caller
 * that cannot supply the passphrase fails once rather than asking again on every operation;
 * a failed renewal is not, so a long-lived process recovers once its passphrase source does.
 * [unlock] with a passphrase in hand (an app's unlock screen) clears a kept failure.
 *
 * [deviceIdentity] gives the flows their `DeviceIdentity` (and its `asSigner()`).
 *
 * Not hardware-backed: code running as the user can capture the passphrase or read the seeds
 * while they are held. [close] zeroes them, best effort.
 */
class SealedDeviceKeys internal constructor(
    private val sealed: SealedFile,
    private val passphrase: () -> ByteArray,
    private val ttlMillis: Long,
    private val nanoTime: () -> Long,
    private val opener: (ByteArray) -> SealedFile.Opened,
    /** Runs the action after the delay (ms), off the caller's thread: the hold's expiry. */
    private val schedule: (Long, () -> Unit) -> Unit,
) : AutoCloseable {
    /**
     * [passphrase] is called only when an unlock is due, and the array it returns is zeroed
     * after use. It may throw (a dismissed dialog), which fails that unlock.
     */
    constructor(
        sealed: SealedFile,
        passphrase: () -> ByteArray,
        ttlMillis: Long = DEFAULT_TTL_MILLIS,
    ) : this(sealed, passphrase, ttlMillis, System::nanoTime, sealed::open, ::scheduleOnExpiryThread)

    init {
        require(ttlMillis > 0) { "custody: the unlock hold must be positive" }
    }

    /** The device's Ed25519 public signing key, from the clear header. */
    val signPublicKey: ByteArray = publicOf(sealed.signerId(DEVICE_SIGNER), "a `$DEVICE_SIGNER` signer")

    /** The device's X25519 public encryption key, from the clear header. */
    val encPublicKey: ByteArray = publicOf(sealed.recipientId, "an X25519 recipient")

    private val lock = Any()
    private var opened: SealedFile.Opened? = null
    private var until = 0L
    private var everUnlocked = false
    private var kept: Exception? = null

    /** Whether the seeds are held now. */
    val isUnlocked: Boolean
        get() = synchronized(lock) { opened != null && nanoTime() - until < 0 }

    /** Unlocks now, asking the passphrase source, unless the seeds are already held. */
    @Throws(Exception::class)
    fun unlock() {
        synchronized(lock) { ensureUnlocked() }
    }

    /**
     * Unlocks now with [passphrase] (zeroed after use), replacing any hold and clearing a
     * kept failure: an unlock screen's retry after a mistyped passphrase.
     */
    @Throws(SealedFile.SealedFileException::class)
    fun unlock(passphrase: ByteArray) {
        synchronized(lock) {
            dropHold()
            kept = null
            openWith(passphrase)
        }
    }

    /**
     * Drops the held seeds now, zeroing them. Not final: the next private operation unlocks
     * again, so an app can lock on idle and keep the instance.
     */
    override fun close() {
        synchronized(lock) { dropHold() }
    }

    /** Signs [message] with the device signer, unlocking if due. */
    @Throws(Exception::class)
    fun sign(message: ByteArray): ByteArray = withSeed({ it.ed25519Seed(DEVICE_SIGNER) }) { seed ->
        Ed25519Engine.sign(seed, message)
    }

    /** Unwraps a space key wrapped for this device's X25519 key, unlocking if due. */
    @Throws(Exception::class)
    fun unwrap(wrapped: ByteArray): ByteArray = withSeed({ it.x25519Seed() }) { seed ->
        VoidbindEncryption.unwrap(wrapped, seed)
    }

    /**
     * This device for the library flows. Building it asks nothing; signing, or reading its
     * `encPrivateKey` (a pairing responder only), unlocks if due.
     */
    fun deviceIdentity(): DeviceIdentity = DeviceIdentity(
        signPublicKey.copyOf(),
        encPublicKey.copyOf(),
        { withSeed({ it.x25519Seed() }) { it.copyOf() } },
        ::sign,
    )

    /** `ed25519:<hex>` for the device signing key. */
    val deviceId: KeyRef get() = KeyRef.ed25519(signPublicKey)

    private fun <T> withSeed(pick: (SealedFile.Opened) -> ByteArray?, use: (ByteArray) -> T): T {
        val seed = synchronized(lock) {
            ensureUnlocked()
            pick(opened!!) ?: error("custody: the sealed file lost an object it was checked to hold")
        }
        try {
            return use(seed)
        } finally {
            seed.fill(0)
        }
    }

    // Any failure to get the passphrase or open fails the unlock: a dismissed dialog
    // throws whatever its source throws.
    @Suppress("TooGenericExceptionCaught")
    private fun ensureUnlocked() {
        kept?.let { throw it }
        if (opened != null && nanoTime() - until < 0) return
        dropHold()
        try {
            openWith(passphrase())
        } catch (e: Exception) {
            if (!everUnlocked) kept = e
            throw e
        }
    }

    private fun openWith(pass: ByteArray) {
        val o = try {
            opener(pass)
        } finally {
            pass.fill(0)
        }
        opened = o
        everUnlocked = true
        // Measured from when the open returned, as Go's is: the KDF itself takes a while.
        until = nanoTime() + ttlMillis * NANOS_PER_MILLI
        // When the hold lapses the seeds are wiped then, not at the next operation: an idle
        // process must not keep them. A later unlock holds a new Opened, so this one's
        // expiry leaves that alone.
        schedule(ttlMillis) {
            synchronized(lock) { if (opened === o) dropHold() }
        }
    }

    private fun dropHold() {
        opened?.close()
        opened = null
    }

    companion object {
        /** The sealed file's Ed25519 signer name (void-which-binds-go `custody.DeviceSigner`). */
        const val DEVICE_SIGNER = "device"

        /** How long an unlock holds the seeds: the reference CLI's `unlockTTL`. */
        const val DEFAULT_TTL_MILLIS: Long = 10 * 60 * 1000L

        private const val NANOS_PER_MILLI = 1_000_000L

        private val expiry = java.util.concurrent.ScheduledThreadPoolExecutor(1) { r ->
            Thread(r, "sealed-device-keys-expiry").apply { isDaemon = true }
        }.apply { removeOnCancelPolicy = true }

        private fun scheduleOnExpiryThread(delayMillis: Long, action: () -> Unit) {
            expiry.schedule(action, delayMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
        }

        private fun publicOf(id: String?, what: String): ByteArray {
            require(id != null) { "custody: the sealed file holds no $what" }
            return KeyRef.parse(id).bytes
        }
    }
}
