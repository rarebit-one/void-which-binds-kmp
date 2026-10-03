package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex

/**
 * The pairing INVITE — the QR/short-code the initiator (an existing, authorised
 * device) renders for the responder (the new device) to scan. It carries the
 * out-of-band session bootstrap over the VISUAL channel:
 *
 *     void-which-binds:pair?v=4&relay=<origin>&session=<id>&salt=<hex>&usr=<ed25519:hex>
 *
 * The salt is hex so it survives a QR/text round-trip unchanged. v3 (ADR-0005 /
 * void-which-binds-go ADR-0007) adds `usr`: the identity (genesis key) the new device is
 * being enrolled into, so the responder can evaluate the initiator's membership
 * BEFORE deriving the SAS. v4 (void-which-binds-go ADR-0013/ADR-0022) is v3's fields
 * under the gen2 `void-which-binds:` scheme; a gen1 invite (`voidbind:`, `v=3`) is
 * refused, not dual-parsed. Scanning the invite off the real initiator's screen is
 * what authenticates these values — a network attacker cannot substitute them
 * without also defeating the SAS ([Pairing]).
 *
 * This is the exact wire contract of void-which-binds-go's `pairflow.EncodeInvite` /
 * `DecodeInvite` — canonical (void-which-binds-go leads; see AGENTS.md). [encode]
 * reproduces Go's `url.Values.Encode()` byte for byte (keys sorted, values
 * query-escaped) so a KMP-rendered invite is indistinguishable from a Go-rendered
 * one; [decode] is tolerant of key order and percent/plus encoding.
 */
object Invite {

    const val SCHEME = "void-which-binds"

    /** The invite payload version; a future field change becomes a parse failure. */
    const val VERSION = "4"

    private const val PREFIX = "$SCHEME:pair?"

    /**
     * The parsed parts of an invite. [user] is the identity (`ed25519:<hex>`) the
     * new device will be a member of — it travels over the visual channel like the
     * salt, and the SAS then binds the initiator's device key to that identity via
     * the membership evaluation.
     */
    class Parsed(val relay: String, val session: String, val salt: ByteArray, val user: String)

    /**
     * Render the invite the responder scans. Refuses an empty relay/session, a
     * salt below the freshness floor ([Pairing.MIN_SALT_LEN]) or an unparseable
     * [usr], matching the Go side's guards.
     */
    fun encode(relay: String, session: String, salt: ByteArray, usr: String): String {
        require(relay.isNotEmpty() && session.isNotEmpty()) { "invite needs a relay and a session" }
        require(salt.size >= Pairing.MIN_SALT_LEN) {
            "invite salt is too short (${salt.size} < ${Pairing.MIN_SALT_LEN})"
        }
        requireUser(usr)
        // Go's url.Values.Encode() writes keys in sorted order; match it so the
        // rendered string is byte-identical across the two implementations.
        val params = listOf(
            "relay" to relay,
            "salt" to Hex.encode(salt),
            "session" to session,
            "usr" to usr,
            "v" to VERSION,
        )
        val query = params.joinToString("&") { (k, v) -> "${queryEscape(k)}=${queryEscape(v)}" }
        return PREFIX + query
    }

    /**
     * Parse an invite URI back into its parts, refusing a wrong scheme, wrong
     * version, malformed salt, a salt below the freshness floor, or a missing /
     * unparseable user.
     */
    @Throws(Exception::class)
    fun decode(uri: String): Parsed {
        require(uri.startsWith(PREFIX)) { "not a $SCHEME pairing invite" }
        val query = uri.substring(PREFIX.length)
        val fields = HashMap<String, String>()
        if (query.isNotEmpty()) {
            for (pair in query.split("&")) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                if (eq < 0) {
                    fields[queryUnescape(pair)] = ""
                } else {
                    fields[queryUnescape(pair.substring(0, eq))] = queryUnescape(pair.substring(eq + 1))
                }
            }
        }
        require(fields["v"] == VERSION) { "invite version ${fields["v"]}, want $VERSION" }
        val relay = fields["relay"].orEmpty()
        val session = fields["session"].orEmpty()
        require(relay.isNotEmpty() && session.isNotEmpty()) { "invite missing relay or session" }
        val salt = Hex.decode(fields["salt"].orEmpty())
        require(salt.size >= Pairing.MIN_SALT_LEN) {
            "invite salt is too short (${salt.size} < ${Pairing.MIN_SALT_LEN})"
        }
        val usr = fields["usr"].orEmpty()
        requireUser(usr)
        return Parsed(relay, session, salt, usr)
    }

    /** #116: the invite names the identity by its one canonical spelling. */
    private fun requireUser(usr: String) {
        try {
            KeyRef.parseCanonicalEd25519(usr)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("invite user: ${e.message}")
        }
    }

    /**
     * Reproduce Go's `url.QueryEscape` (query-component mode): keep the unreserved
     * set `A-Za-z0-9-_.~`, encode a space as '+', and percent-encode everything
     * else as uppercase `%XX` over the UTF-8 bytes.
     */
    private fun queryEscape(s: String): String {
        val bytes = s.encodeToByteArray()
        val out = StringBuilder(bytes.size)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            when {
                c.toChar() in 'A'..'Z' || c.toChar() in 'a'..'z' || c.toChar() in '0'..'9' ||
                    c.toChar() == '-' || c.toChar() == '_' || c.toChar() == '.' || c.toChar() == '~' ->
                    out.append(c.toChar())

                c == ' '.code -> out.append('+')

                else -> {
                    out.append('%')
                    out.append(HEX[c ushr 4])
                    out.append(HEX[c and 0x0F])
                }
            }
        }
        return out.toString()
    }

    /** Reverse [queryEscape]: '+' → space, `%XX` → byte, decoded as UTF-8. */
    private fun queryUnescape(s: String): String {
        val out = ArrayList<Byte>(s.length)
        var i = 0
        while (i < s.length) {
            when (val c = s[i]) {
                '+' -> {
                    out.add(' '.code.toByte())
                    i++
                }

                '%' -> {
                    require(i + 2 < s.length) { "truncated percent-escape in invite" }
                    val hi = hexVal(s[i + 1])
                    val lo = hexVal(s[i + 2])
                    out.add(((hi shl 4) or lo).toByte())
                    i += 3
                }

                else -> {
                    out.add(c.code.toByte())
                    i++
                }
            }
        }
        return out.toByteArray().decodeToString()
    }

    private val HEX = "0123456789ABCDEF".toCharArray()

    private fun hexVal(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("invalid percent-escape digit '$c' in invite")
    }
}
