package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.Ed25519Signer
import kotlin.concurrent.Volatile

/**
 * An enrolled device's live credential under the `Device` authorization scheme
 * (`Authorization: Device <cert>~<proof>`): the long-lived enrolment cert plus the
 * [PossessionProof] currently in force, re-minted when it is about to lapse or when
 * a relying party refuses it.
 *
 * This class owns the WIRE FORMAT — the `~` join (void-which-binds-go
 * `enrolment.CredentialSeparator`; a tilde is outside the base64url alphabet so it
 * can never occur inside either half) and the `Device ` scheme prefix. The proof
 * bytes are [PossessionProof]'s and the signing key is the [signer]'s: on a phone the
 * hardware-sealed Ed25519 device key from `DeviceKeyStore.asSigner()` (ADR-0001 — the
 * seed is unsealed only transiently to sign, and signing may need a recent
 * biometric); in tests, a software key.
 *
 * **Why not sign every request.** On Android each signature unseals the seed behind a
 * user-presence window, so a per-request proof would mean a biometric prompt every
 * half-minute. Instead one proof is minted for [ttlSeconds] and REUSED for
 * [reuseForSeconds] (default: the ttl minus [PossessionProof.SKEW_SECONDS], so a
 * presentation is retired proactively while the server would still honour it);
 * [current] hands back the live presentation or re-mints, and [refresh] is the forced
 * re-mint a transport uses after a `401` ([DeviceAuthPolicy]). The server never caps
 * a proof's ttl — the client chooses; the Go client's default is 2 minutes.
 *
 * Not internally locked (`commonMain` carries no lock primitive): drive one instance
 * from one authentication path — the transport decorator — so a re-mint never
 * double-prompts for presence.
 *
 * @param certToken the enrolment cert token this device presents (from pairing/enrolment).
 * @param signer the device signing key — `DeviceKeyStore.asSigner()` in an app.
 * @param clock unix seconds now; injected so the reuse window is testable.
 */
class DeviceCredential(
    val certToken: String,
    private val signer: Ed25519Signer,
    private val clock: () -> Long,
    val ttlSeconds: Long = PossessionProof.DEFAULT_TTL_SECONDS,
    val reuseForSeconds: Long = ttlSeconds - PossessionProof.SKEW_SECONDS,
) {
    init {
        require(certToken.isNotEmpty()) { "a device credential needs a cert token" }
        require(!certToken.contains(SEPARATOR)) { "cert token must not contain the '$SEPARATOR' separator" }
        require(ttlSeconds > 0) { "ttlSeconds must be positive" }
        require(reuseForSeconds in 1..ttlSeconds) { "reuseForSeconds must be in 1..ttlSeconds" }
    }

    /**
     * One minted presentation: the cert and a proof issued at [issuedAt] (unix
     * seconds), which the server honours until [expiresAt] (strict).
     */
    class Presentation(val cert: String, val proof: String, val issuedAt: Long, val expiresAt: Long) {
        /** The credential VALUE — `<cert>~<proof>` — the part after `Device `. */
        val value: String get() = format(cert, proof)

        /** The full `Authorization` header value: `Device <cert>~<proof>`. */
        val headerValue: String get() = "$SCHEME $value"

        override fun toString(): String = "Presentation(issuedAt=$issuedAt, expiresAt=$expiresAt)"
    }

    @Volatile
    private var live: Presentation? = null

    /**
     * The presentation to send now — the live one while it is inside the reuse
     * window, else a fresh mint (which on a phone may prompt for user presence).
     */
    fun current(): Presentation {
        val p = live
        if (p != null && clock() < p.issuedAt + reuseForSeconds) return p
        return refresh()
    }

    /** The `Authorization` header value to send now — `Device <cert>~<proof>`. */
    fun headerValue(): String = current().headerValue

    /** Force a fresh proof — after a `401`, or on wake. Replaces the live presentation. */
    fun refresh(): Presentation = mint(certToken, signer, clock(), ttlSeconds).also { live = it }

    companion object {
        /** The authorization scheme name. */
        const val SCHEME = "Device"

        /** The header a device credential is carried in. */
        const val HEADER = "Authorization"

        /** The enrolment separator joining the cert and the possession proof. */
        const val SEPARATOR = "~"

        /**
         * The request header a device uses to present the membership ops it knows
         * beside its credential (void-which-binds-go `rp.MembershipHeader`, ADR-0005): a
         * comma-separated list of op tokens, at most [MAX_PRESENTED_OPS]. An RP merges
         * them with its own log before evaluating, so a device admitted by a phone
         * this RP has never met still authenticates on first contact.
         */
        const val MEMBERSHIP_HEADER = "Void-Which-Binds-Membership"

        /** The most ops [MEMBERSHIP_HEADER] may carry (void-which-binds-go `rp.MaxPresentedOps`). */
        const val MAX_PRESENTED_OPS = 64

        /**
         * The [MEMBERSHIP_HEADER] value for [ops]: de-duplicated, in hash order, capped
         * at [MAX_PRESENTED_OPS]; empty when there is nothing to present (send no header).
         */
        fun membershipHeaderValue(ops: List<String>): String =
            one.rarebit.voidwhichbinds.Membership.merge(ops).take(MAX_PRESENTED_OPS).joinToString(",")

        /** Build the credential VALUE `<cert>~<proof>` (the part after `Device `). Pure. */
        fun format(cert: String, proof: String): String {
            require(cert.isNotEmpty() && proof.isNotEmpty()) { "a device credential needs a cert and a proof" }
            require(!cert.contains(SEPARATOR)) { "cert must not contain the '$SEPARATOR' separator" }
            return cert + SEPARATOR + proof
        }

        /** The full header value `Device <cert>~<proof>`. Pure. */
        fun headerValue(cert: String, proof: String): String = "$SCHEME ${format(cert, proof)}"

        /** Split a credential VALUE (or a full `Device …` header value) back into (cert, proof). */
        fun parse(value: String): Pair<String, String> {
            val v = if (value.startsWith("$SCHEME ")) value.substring(SCHEME.length + 1) else value
            val i = v.indexOf(SEPARATOR)
            require(i > 0 && i < v.length - 1) { "malformed device credential: expected <cert>$SEPARATOR<proof>" }
            return v.substring(0, i) to v.substring(i + 1)
        }

        /** True when [headerValue] is a `Device …` credential (as opposed to `Bearer …` or none). */
        fun isDeviceHeader(headerValue: String?): Boolean = headerValue?.startsWith("$SCHEME ") == true

        /**
         * Mint one [Presentation] for [certToken] at [now] (unix seconds): a fresh
         * [PossessionProof] signed by [signer], joined to the cert. Stateless — use a
         * [DeviceCredential] instance to get the reuse window.
         */
        fun mint(
            certToken: String,
            signer: Ed25519Signer,
            now: Long,
            ttlSeconds: Long = PossessionProof.DEFAULT_TTL_SECONDS,
        ): Presentation {
            val ttl = if (ttlSeconds <= 0) PossessionProof.DEFAULT_TTL_SECONDS else ttlSeconds
            val proof = PossessionProof.mint(certToken, signer, now, ttl)
            return Presentation(certToken, proof, now, now + ttl)
        }
    }
}
