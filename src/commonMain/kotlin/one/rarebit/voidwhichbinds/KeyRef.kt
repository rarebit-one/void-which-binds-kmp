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
    }
}
