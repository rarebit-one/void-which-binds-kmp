package one.rarebit.voidwhichbinds

/**
 * Identity-defining protocol constants shared with void-which-binds-go (and heyarr upstream).
 *
 * ⚠️ These strings are part of the cryptographic identity. Changing any of them
 * derives *different* keys / *incompatible* tokens — it is a silent, total break
 * of wire compatibility, not a rename. DO NOT edit them to "clean them up"; the
 * `heyarr` heritage in the names and HRP is deliberate and load-bearing.
 */
object Labels {
    /**
     * HKDF `info` label used to derive the user identity Ed25519 seed from the
     * recovery secret. Byte-identical to void-which-binds-go.
     */
    const val HKDF_USER_IDENTITY_ED25519_SEED = "heyarr/recovery/v1/user-identity-ed25519-seed"

    /** Human-readable-part for the bech32m recovery secret. */
    const val RECOVERY_HRP = "heyarr"

    /** Algorithm prefix for identity/signing keys (Ed25519). */
    const val ALG_ED25519 = "ed25519"

    /** Algorithm prefix for device encryption keys (X25519). */
    const val ALG_X25519 = "x25519"

    /**
     * Cert token payload version currently emitted/accepted. v2 (ADR-0049) binds
     * the device X25519 encryption key (denc). MUST be 2 to interop with
     * void-which-binds-go: its `enrolment.CertUser` (called first by `rp.Verify`) requires
     * v==2, so a v1 cert is refused by every Go relying party.
     */
    const val CERT_VERSION = 2

    /** Recovery secret size in bytes (256-bit). */
    const val RECOVERY_SECRET_LEN = 32
}
