package one.rarebit.voidwhichbinds.crypto

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal actual fun aeadIetfSeal(key: ByteArray, nonce12: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
    val c = Cipher.getInstance("ChaCha20-Poly1305") // fresh instance = no pooled-cipher nonce guard
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce12))
    if (aad.isNotEmpty()) c.updateAAD(aad)
    return c.doFinal(plaintext) // ciphertext ‖ 16-byte tag
}

internal actual fun aeadIetfOpen(key: ByteArray, nonce12: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
    val c = Cipher.getInstance("ChaCha20-Poly1305")
    c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce12))
    if (aad.isNotEmpty()) c.updateAAD(aad)
    return c.doFinal(ciphertext)
}
