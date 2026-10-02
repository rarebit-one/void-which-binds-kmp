package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex

/**
 * Algorithm-prefixed public-key rendering, matching void-which-binds-go exactly:
 * `ed25519:<hex>` for identity/signing keys, `x25519:<hex>` for device
 * encryption keys. The prefix is part of the wire string — a bare hex key is
 * not a valid [KeyRef].
 */
data class KeyRef(val alg: String, val bytes: ByteArray) {

    /** Rendered form, e.g. `ed25519:3b6a...`. */
    fun render(): String = "$alg:${Hex.encode(bytes)}"

    override fun toString(): String = render()

    override fun equals(other: Any?): Boolean = other is KeyRef && alg == other.alg && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = 31 * alg.hashCode() + bytes.contentHashCode()

    companion object {
        fun ed25519(bytes: ByteArray): KeyRef = KeyRef(Labels.ALG_ED25519, bytes)
        fun x25519(bytes: ByteArray): KeyRef = KeyRef(Labels.ALG_X25519, bytes)

        /** Parse an `<alg>:<hex>` string. Throws on a missing/unknown prefix or bad hex. */
        fun parse(s: String): KeyRef {
            val idx = s.indexOf(':')
            require(idx > 0) { "key ref missing '<alg>:' prefix: '$s'" }
            val alg = s.substring(0, idx)
            require(alg == Labels.ALG_ED25519 || alg == Labels.ALG_X25519) {
                "unknown key algorithm: '$alg'"
            }
            return KeyRef(alg, Hex.decode(s.substring(idx + 1)))
        }

        /**
         * The raw 32-byte Ed25519 key of a key string that NAMES an identity — a field
         * of a signed body (an op's `usr`, `by` or `dev`, a cosig's `by`, a cert's
         * `dev`, an invite's `usr`). It accepts exactly one spelling per key, [render]'s:
         * `ed25519:<64 lowercase hex>` with no surrounding whitespace. Throws
         * [IllegalArgumentException] for anything else, an uppercase-hex or padded
         * rendering of a valid key included: wherever a key string is a map key or a
         * set member, a second spelling is one key counted as two identities.
         * Mirrors void-which-binds-go `identity.ParseCanonicalPublicKey` (#116).
         */
        fun parseCanonicalEd25519(s: String): ByteArray {
            val ref = parse(s)
            require(ref.alg == Labels.ALG_ED25519 && ref.bytes.size == ED25519_KEY_LEN) {
                "'$s' is not a 32-byte ed25519 key"
            }
            val canonical = ref.render()
            require(canonical == s) { "'$s' is not the canonical rendering '$canonical'" }
            return ref.bytes
        }

        private const val ED25519_KEY_LEN = 32
    }
}
