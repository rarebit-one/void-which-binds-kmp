package one.rarebit.voidwhichbinds.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.ChaCha20Poly1305

private val aeadAlgorithm = CryptographyProvider.Default.get(ChaCha20Poly1305)
private val aeadKeyDecoder = aeadAlgorithm.keyDecoder()

@OptIn(DelicateCryptographyApi::class)
internal actual fun aeadIetfSeal(key: ByteArray, nonce12: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray =
    aeadKeyDecoder.decodeFromByteArrayBlocking(
        ChaCha20Poly1305.Key.Format.RAW,
        key,
    ).cipher().encryptWithIvBlocking(nonce12, plaintext, aad)

@OptIn(DelicateCryptographyApi::class)
internal actual fun aeadIetfOpen(key: ByteArray, nonce12: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray =
    aeadKeyDecoder.decodeFromByteArrayBlocking(
        ChaCha20Poly1305.Key.Format.RAW,
        key,
    ).cipher().decryptWithIvBlocking(nonce12, ciphertext, aad)
