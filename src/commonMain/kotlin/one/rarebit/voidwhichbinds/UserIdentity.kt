package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.random.CryptographyRandom
import one.rarebit.voidwhichbinds.crypto.Ed25519Group

/**
 * A person's **sovereign user identity**: the Ed25519 signing key that IS the
 * account. It is derived DETERMINISTICALLY from a [RecoverySecret] (the value the
 * user writes down), so the same secret reconstructs the SAME public key on any
 * device with no server — that is what makes recovery restore *authority* offline
 * (ADR-0022 / ADR-0048): a recovered user re-issues device certs that verify
 * against the already-pinned key and nothing is re-pinned.
 *
 * The derivation is byte-identical to void-which-binds-go's `recovery.DeriveUserSeed`:
 *
 *     userSeed = HKDF-SHA256(ikm = recovery-secret, salt = ∅,
 *                            info = "void-which-binds/recovery/v1/user-identity-ed25519-seed",
 *                            len = 32)
 *     userPub  = Ed25519 public key of userSeed        (see [Ed25519Group])
 *
 * The public half is computed with the pure-Kotlin [Ed25519Group] BECAUSE the JDK
 * (and Apple) providers refuse to derive an Ed25519 public key from a raw seed;
 * signing itself uses the vetted provider ([Ed25519Engine]). Proven against a
 * live void-which-binds-go KAT (secret → seed → public key).
 *
 * The raw signing seed never leaves this object except through [signer]/[sign].
 */
class UserIdentity private constructor(
    /** The recovery secret to display ONCE and have the user store offline. */
    val recovery: RecoverySecret,
    internal val userSeed: ByteArray,
    /** The user identity's 32-byte Ed25519 public key — the value peers pin. */
    val userPublicKey: ByteArray,
) {
    /** The user identity rendered as `ed25519:<hex>` — the pinned principal. */
    val userId: KeyRef get() = KeyRef.ed25519(userPublicKey)

    /** The printable fingerprint of the user key ([UserFingerprint]). */
    val fingerprint: String get() = UserFingerprint.of(userPublicKey)

    /** An [Ed25519Signer] over the user key — used to sign device enrolment certs. */
    fun signer(): Ed25519Signer = Ed25519Signer { message -> Ed25519Engine.sign(userSeed, message) }

    /** Sign [message] directly with the user key. */
    fun sign(message: ByteArray): ByteArray = Ed25519Engine.sign(userSeed, message)

    companion object {
        private val hkdf = CryptographyProvider.Default.get(HKDF)

        /**
         * Mint a BRAND-NEW identity from fresh CSPRNG entropy. The returned
         * [recovery] secret is shown to the user and written down offline — losing
         * every copy is losing the account (ADR-0021/0022). This library never
         * persists it; an app that keeps a sealed copy (Cruciform does, behind a
         * strong biometric) owns that decision.
         */
        fun create(): UserIdentity =
            fromSecret(RecoverySecret.of(CryptographyRandom.Default.nextBytes(Labels.RECOVERY_SECRET_LEN)))

        /**
         * RESTORE an identity from the recovery string the user wrote down. Fails
         * LOUD on a transcription slip (the bech32m checksum in [RecoverySecret.parse]
         * throws) — it never derives a plausible-but-wrong identity.
         *
         * `@Throws` so the rejection crosses the ObjC/Swift boundary as a catchable
         * error (Kotlin's `IllegalArgumentException` is unchecked and would otherwise
         * bridge as an uncatchable crash) — a mistyped secret in the iOS/Swift app
         * must surface as "re-read the secret", not a fatal.
         */
        @Throws(IllegalArgumentException::class)
        fun restore(secret: String): UserIdentity = fromSecret(RecoverySecret.parse(secret))

        /** Derive the identity from an already-parsed [RecoverySecret]. */
        fun fromSecret(secret: RecoverySecret): UserIdentity {
            val seed = hkdf
                .secretDerivation(
                    SHA256,
                    32.bytes,
                    salt = ByteArray(0), // Go passes a nil salt; RFC 5869 → zero-filled, byte-equal
                    info = Labels.HKDF_USER_IDENTITY_ED25519_SEED.encodeToByteArray(),
                )
                .deriveSecretToByteArrayBlocking(secret.bytes)
            val pub = Ed25519Group.publicKeyFromSeed(seed)
            return UserIdentity(secret, seed, pub)
        }
    }
}
