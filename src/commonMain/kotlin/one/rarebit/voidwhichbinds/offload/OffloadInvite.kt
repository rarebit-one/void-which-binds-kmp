package one.rarebit.voidwhichbinds.offload

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.UrlQuery

/**
 * The cruciform-OFFLOAD deep links the phone half consumes (ADR-0098). These are a
 * heyarr-SPECIFIC extension, NOT the voidbind protocol proper, so they live in this
 * `offload` package and mirror heyarr-core's `internal/personalstate/client/cruciform`
 * wire byte-for-byte rather than a void-which-binds-go encoding:
 *
 *  - the one-time PAIRING invite the desktop shows as a QR and the phone scans:
 *      voidbind:offload-pair?v=1&relay=<origin>&session=<id>&salt=<hex>
 *  - the recurring UNWRAP wake ping the phone receives over push (or discovers on
 *    the LAN), an opaque pointer to the relay session the desktop opened:
 *      voidbind:unwrap?relay=<origin>&session=<id>
 *
 * Both carry only public values — a relay/session pointer and a fresh salt — never
 * a key or a secret; the visual channel (the scanned QR) and the SAS are what
 * authenticate the pairing, and the unwrap exchange over the relay is separately
 * signed.
 */
public object OffloadDeepLink {
    private const val SCHEME = "voidbind"
    private const val PAIR_OPAQUE = "offload-pair"
    private const val UNWRAP_OPAQUE = "unwrap"
    private const val PAIR_VERSION = "1"

    /** The minimum session-salt length, matching void-which-binds-go `pairing.MinSaltLen`. */
    public const val MIN_SALT_LEN: Int = 16

    /** A decoded offload pairing invite. */
    public data class PairInvite(val relayBase: String, val session: String, val salt: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is PairInvite && relayBase == other.relayBase && session == other.session &&
                salt.contentEquals(other.salt)

        override fun hashCode(): Int = (31 * relayBase.hashCode() + session.hashCode()) * 31 + salt.contentHashCode()
    }

    /** A decoded offload unwrap wake-ping. */
    public data class WakePing(val relayBase: String, val session: String)

    /**
     * Encode a pairing invite exactly as heyarr-core's `EncodeInvite` does — the
     * query keys are emitted in sorted order (relay, salt, session, v), matching Go's
     * `url.Values.Encode`, so a Kotlin-rendered invite is byte-identical to the Go one.
     */
    public fun encodePairInvite(relayBase: String, session: String, salt: ByteArray): String {
        require(relayBase.isNotEmpty() && session.isNotEmpty()) { "offload invite needs a relay and a session" }
        require(salt.size >= MIN_SALT_LEN) { "offload invite salt is ${salt.size} bytes, want at least $MIN_SALT_LEN" }
        val params = listOf(
            "relay" to relayBase,
            "salt" to Hex.encode(salt),
            "session" to session,
            "v" to PAIR_VERSION,
        )
        return "$SCHEME:$PAIR_OPAQUE?" + UrlQuery.encode(params)
    }

    /** Parse a `voidbind:offload-pair?…` invite, or throw [IllegalArgumentException]. */
    public fun parsePairInvite(uri: String): PairInvite {
        val q = queryOf(uri, PAIR_OPAQUE)
        require(q["v"] == PAIR_VERSION) { "offload invite version ${q["v"]}, want $PAIR_VERSION" }
        val relay = q["relay"].orEmpty()
        val session = q["session"].orEmpty()
        require(relay.isNotEmpty() && session.isNotEmpty()) { "offload invite missing relay or session" }
        val salt = Hex.decode(q["salt"].orEmpty())
        require(salt.size >= MIN_SALT_LEN) { "offload invite salt is ${salt.size} bytes, want at least $MIN_SALT_LEN" }
        return PairInvite(relay, session, salt)
    }

    /** Encode an unwrap wake-ping, matching heyarr-core / void-which-binds-go `notify.EncodeUnwrap`. */
    public fun encodeWakePing(relayBase: String, session: String): String {
        require(relayBase.isNotEmpty() && session.isNotEmpty()) { "unwrap ping needs a relay and a session" }
        return "$SCHEME:$UNWRAP_OPAQUE?" + UrlQuery.encode(listOf("relay" to relayBase, "session" to session))
    }

    /** Parse a `voidbind:unwrap?…` wake-ping, or throw [IllegalArgumentException]. */
    public fun parseWakePing(uri: String): WakePing {
        val q = queryOf(uri, UNWRAP_OPAQUE)
        val relay = q["relay"].orEmpty()
        val session = q["session"].orEmpty()
        require(relay.isNotEmpty() && session.isNotEmpty()) { "unwrap ping missing relay or session" }
        return WakePing(relay, session)
    }

    /** Split "voidbind:<opaque>?<query>" and decode the query, refusing a wrong scheme/opaque. */
    private fun queryOf(uri: String, opaque: String): Map<String, String> {
        val prefix = "$SCHEME:$opaque?"
        require(uri.startsWith(prefix)) { "not a $SCHEME:$opaque link" }
        return UrlQuery.decode(uri.substring(prefix.length))
    }
}
