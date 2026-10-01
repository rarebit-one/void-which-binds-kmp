package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.UrlQuery

/**
 * The web-login QR — the code a relying party (All Thing, a homelab web app)
 * renders in a browser for the device to scan (WhatsApp-Web pattern):
 *
 *     void-which-binds:login?rp=<origin>&id=<login-id>
 *
 * It carries ONLY the RP origin and the login id; the device fetches the full,
 * signed challenge from the RP by id ([net.WebLoginClient.fetchChallenge]), so the
 * QR stays tiny and the RP is the single source of truth for what is signed.
 *
 * This is the exact wire contract of void-which-binds-go's `weblogin.EncodeLogin` /
 * `DecodeLogin` — canonical (void-which-binds-go leads). [encode] reproduces Go's
 * `url.Values.Encode()` byte for byte (keys SORTED → `id` before `rp`, values
 * query-escaped); [decode] is tolerant of key order and percent/plus encoding.
 */
object LoginQr {

    const val SCHEME = "void-which-binds"
    private const val PREFIX = "$SCHEME:login?"

    /** The parsed parts of a login QR. */
    class Parsed(val rp: String, val id: String)

    /** Render the QR the browser shows. Refuses an empty rp or id, matching Go. */
    fun encode(rp: String, id: String): String {
        require(rp.isNotEmpty() && id.isNotEmpty()) { "a login QR needs an rp and an id" }
        return PREFIX + UrlQuery.encode(listOf("rp" to rp, "id" to id))
    }

    /** Parse a login QR back into (rp, id), refusing a wrong scheme or a missing field. */
    fun decode(uri: String): Parsed {
        require(uri.startsWith(PREFIX)) { "not a $SCHEME login QR" }
        val fields = UrlQuery.decode(uri.substring(PREFIX.length))
        val rp = fields["rp"].orEmpty()
        val id = fields["id"].orEmpty()
        require(rp.isNotEmpty() && id.isNotEmpty()) { "login QR missing rp or id" }
        return Parsed(rp, id)
    }
}

/**
 * The single dispatch point for the app's QR scanner: a scanned `void-which-binds:` code
 * is either a **web-login** ([Login]) or a **pairing invite** ([Pair]). The Scan
 * screen calls [parse] and branches on the type — login opens the approval sheet,
 * pair opens the SAS-compare flow.
 */
sealed class VoidbindQr {
    /** A web-login QR: approve a browser sign-in. */
    class Login(val request: LoginQr.Parsed) : VoidbindQr()

    /** A pairing invite QR: enrol as a new device against an existing one. */
    class Pair(val invite: Invite.Parsed) : VoidbindQr()

    companion object {
        private const val LOGIN_PREFIX = "${LoginQr.SCHEME}:login?"
        private const val PAIR_PREFIX = "${Invite.SCHEME}:pair?"

        /** Classify and parse a scanned QR. Throws on anything that is not a void-which-binds QR. */
        fun parse(uri: String): VoidbindQr = when {
            uri.startsWith(LOGIN_PREFIX) -> Login(LoginQr.decode(uri))
            uri.startsWith(PAIR_PREFIX) -> Pair(Invite.decode(uri))
            else -> throw IllegalArgumentException("not a void-which-binds QR: '${uri.take(32)}…'")
        }
    }
}
