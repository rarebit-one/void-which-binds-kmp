package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pins the pure-Kotlin Ed25519 public-key derivation ([Ed25519Group]) against
 * void-which-binds-go. Each (seed, pub) pair was produced by Go's
 * `ed25519.NewKeyFromSeed(seed).Public()` on the seed void-which-binds-go's
 * `recovery.DeriveUserSeed` derives — the exact chain [UserIdentity] runs. Ed25519
 * is deterministic, so a byte-mismatch here is a broken identity, not a nuance.
 */
class Ed25519GroupTest {

    // (recovery-derived user seed) -> (Ed25519 public key), captured from void-which-binds-go.
    private val vectors = listOf(
        "d84eda0841e8fa2bb238e27b9bf32b809fe8f2ff7744c0c1e06527b7614414ee" to
            "d79fad7575f432e2f4915113b7a89773f7a187305d6823d2aab21121687838f9",
        "dc705c000fa4940080c936e511de64a58b5ac0017c973dec94819669dd3309ad" to
            "847bd05c7d4cb14796b6de05285ca7694ac9be8195b18c284ab767da0c1ad794",
        "dc89c49bfccfdc8fec90c63da3bf5b5dde302ff643aecca97465bee46862c15c" to
            "d679c23b962fa8747020404d8dce9ec84709e21fed0f7583b5ee797dd7d06578",
        "f0a51b305e5237547ba4283b91dec980d08ee40a3e333af86d011678fa6a6c60" to
            "22204e5416ff89181f8f0c3d5441439ab794371f7af94e8f90408a0640d99885",
    )

    @Test
    fun publicKeyFromSeedMatchesVoidbindGo() {
        for ((seedHex, pubHex) in vectors) {
            assertEquals(
                pubHex,
                Hex.encode(Ed25519Group.publicKeyFromSeed(Hex.decode(seedHex))),
                "Ed25519 pub-from-seed must match Go byte-for-byte",
            )
        }
    }

    // A vector INDEPENDENT of void-which-binds-go: this (seed → public key) pair is
    // cross-validated against Go's crypto/ed25519 stdlib AND OpenSSL (Python
    // `cryptography`) — both derive the same public key, so it pins [Ed25519Group]
    // to the world's reference implementations, not just to our own KAT generator.
    @Test
    fun matchesGoStdlibAndOpenssl() {
        val seed = Hex.decode("9d61b19deffbadb01ab1eda5d5a55118be4d7c7c1acd48b4f8b3f0e7e13be6f6")
        val pub = "0a5b4edbb98b1e8963da9c8346b30611b4bda367f6b99f33849e968687e79510"
        assertEquals(pub, Hex.encode(Ed25519Group.publicKeyFromSeed(seed)))
    }
}
