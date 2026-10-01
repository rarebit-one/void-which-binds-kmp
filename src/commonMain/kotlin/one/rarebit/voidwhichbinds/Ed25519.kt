package one.rarebit.voidwhichbinds

/**
 * Ed25519 sign/verify seams. The pure-Kotlin domain (cert encode/verify) depends
 * only on these interfaces; the actual curve arithmetic is supplied by the
 * platform — the [DeviceKeyStore] on-device (hardware-backed), or a software
 * implementation in tests. This keeps `commonMain` free of any crypto backend.
 */
fun interface Ed25519Signer {
    /** Produce a 64-byte Ed25519 signature over [message]. */
    fun sign(message: ByteArray): ByteArray
}

fun interface Ed25519Verifier {
    /** Verify a 64-byte Ed25519 [signature] over [message] against a 32-byte [publicKey]. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}
