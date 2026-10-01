package one.rarebit.voidwhichbinds

/**
 * Minting the FIRST device enrolment cert for a freshly created (or restored)
 * identity — the "add THIS device to my own new account" step, where the user
 * identity and the device are on the same phone, so the user key self-signs the
 * device's cert with no pairing handshake.
 *
 * (Adding a *second* device instead goes over the relay with the SAS handshake —
 * [net.PairflowInitiator]/[net.PairflowResponder]; this is only the bootstrap
 * case where one device holds both keys.)
 *
 * The cert is a v2 [Cert] (byte-identical to void-which-binds-go), signed by the user key,
 * that a void-which-binds-go relying party accepts unchanged.
 */
object Enrolment {

    /** A generous default device-cert lifetime (90 days), matching the CLI. */
    const val DEFAULT_LIFETIME_SECONDS: Long = 90L * 24 * 60 * 60

    /**
     * Self-sign this device's enrolment cert with [identity]'s user key, binding
     * [device]'s signing and encryption public keys. [issuedAt] is unix seconds
     * (the app supplies the clock — `commonMain` has none).
     */
    fun selfEnrol(
        identity: UserIdentity,
        device: DeviceIdentity,
        issuedAt: Long,
        lifetimeSeconds: Long = DEFAULT_LIFETIME_SECONDS,
    ): String = Cert(
        version = Labels.CERT_VERSION,
        user = identity.userId,
        device = KeyRef.ed25519(device.signPublicKey),
        deviceEnc = KeyRef.x25519(device.encPublicKey),
        issuedAt = issuedAt,
        expiresAt = issuedAt + lifetimeSeconds,
    ).encode(identity.signer())
}
