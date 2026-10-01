package one.rarebit.voidwhichbinds.crypto

// IETF ChaCha20-Poly1305 (12-byte nonce) AEAD, platform-provided. On JVM a fresh
// javax Cipher per op — SunJCE forbids reusing one Cipher with the same (key,nonce),
// which cryptography-kotlin's pooled JDK cipher hits on repeated/round-trip decrypts.
internal expect fun aeadIetfSeal(key: ByteArray, nonce12: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray
internal expect fun aeadIetfOpen(key: ByteArray, nonce12: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray
