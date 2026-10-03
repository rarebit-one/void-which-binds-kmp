package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.approval.Approval
import one.rarebit.voidwhichbinds.approval.Handle
import one.rarebit.voidwhichbinds.crypto.UrlQuery

/**
 * The **same-device (app-to-app) handoff** URI — how a relying-party app on the
 * SAME phone as the authenticator hands it a login (or a pairing invite) without a
 * second phone to scan a QR. The Singpass app-to-app model: ONE authenticator, N
 * RPs, the RP opens the authenticator by deep link and resumes when it finishes.
 *
 *     void-which-binds:login?rp=<origin>&id=<login-id>[&callback=<app-scheme-uri>]
 *     void-which-binds:pair?v=4&relay=&session=&salt=<hex>&usr=<ed25519:hex>[&callback=<app-scheme-uri>]
 *
 * This is the EXACT QR tuple ([LoginQr] / [Invite] — the void-which-binds-go wire, which
 * stays byte-identical) plus one optional, authenticator-local `callback` key. The
 * tuple is the contract; `callback` is a UX convenience the RP may set to have the
 * authenticator foreground it again after approval. It is never part of anything
 * signed and never reaches the RP server.
 *
 * # Security posture (see docs/adr/0003-app-to-app-deeplink-handoff.md)
 *
 * - The link carries NO secret and NO result: a login is approved the same way a
 *   scanned QR is — the authenticator pulls the challenge from `rp`, shows the human
 *   the origin, and signs hardware-gated after an explicit tap. A deep link can never
 *   auto-approve, and the RP learns the outcome ONLY by polling its own broker
 *   (`GET /login/{id}`) — the callback is launched bare, with nothing appended.
 * - The URI is untrusted input from another app. `rp`/`id` are validated by the QR
 *   parsers; `callback` is accepted only when [isWellFormedCallback] — a private
 *   app scheme, not `http(s)`/`javascript`/`file`/`content`/`intent`/`void-which-binds`,
 *   no whitespace or control characters — and is otherwise silently dropped (the
 *   approval still proceeds; the RP simply is not foregrounded).
 */
object VoidbindDeepLink {

    /** The optional query key naming the URI to launch after a successful approval. */
    const val CALLBACK = "callback"

    /** Longest callback accepted; anything larger is treated as malformed. */
    const val MAX_CALLBACK_LENGTH = 2048

    /** A parsed handoff: the same shapes as [VoidbindQr], plus the validated callback. */
    sealed class Parsed {
        /** The callback the RP asked to be foregrounded with, or null if absent/malformed. */
        abstract val callback: String?

        /** A login handoff — approve a sign-in at [rp] for login [id]. */
        class Login(val rp: String, val id: String, override val callback: String?) : Parsed() {
            /** The bare QR tuple (no callback), byte-identical to what the RP's broker minted. */
            val tuple: String get() = LoginQr.encode(rp, id)
        }

        /** A pairing-invite handoff — join as the new device against [invite]. */
        class Pair(val invite: Invite.Parsed, override val callback: String?) : Parsed() {
            /** The bare invite (no callback), byte-identical to the initiator's rendering. */
            val tuple: String get() = Invite.encode(invite.relay, invite.session, invite.salt, invite.user)
        }
    }

    /**
     * Build the login handoff URI an RP app launches. Without a [callback] this IS
     * the QR string ([LoginQr.encode]); with one, the `callback` key is appended
     * (query-escaped). Refuses an empty rp/id or a malformed callback — an RP should
     * fail at build time, not discover its callback was dropped on the phone.
     */
    fun loginUri(rp: String, id: String, callback: String? = null): String =
        withCallback(LoginQr.encode(rp, id), callback)

    /**
     * Build the login handoff URI from the QR tuple the RP already holds — the `qr`
     * field its broker returned from `POST /login` — so the RP never re-encodes the
     * wire itself. The tuple is parsed (so a non-login string is refused) and
     * re-rendered canonically.
     */
    fun loginUriFromTuple(tuple: String, callback: String? = null): String {
        val parsed = LoginQr.decode(tuple)
        return loginUri(parsed.rp, parsed.id, callback)
    }

    /**
     * Build the pairing handoff URI from an invite tuple (the initiator's QR string)
     * plus an optional callback. Parsed and re-rendered canonically, like [loginUri].
     */
    fun pairUri(inviteTuple: String, callback: String? = null): String {
        val inv = Invite.decode(inviteTuple)
        return withCallback(Invite.encode(inv.relay, inv.session, inv.salt, inv.user), callback)
    }

    /**
     * Parse an incoming handoff URI. Classification and the rp/id (or invite) fields
     * go through the QR parsers, so a deep link is exactly as strict as a scan; the
     * `callback` is read separately and kept only if [isWellFormedCallback]. Throws
     * (like [VoidbindQr.parse]) on anything that is not a void-which-binds login/pair URI.
     */
    fun parse(uri: String): Parsed {
        val trimmed = uri.trim()
        val callback = callbackOf(trimmed)
        return when (val qr = VoidbindQr.parse(trimmed)) {
            is VoidbindQr.Login -> Parsed.Login(qr.request.rp, qr.request.id, callback)
            is VoidbindQr.Pair -> Parsed.Pair(qr.invite, callback)
        }
    }

    /** Non-throwing [parse]: null for anything that is not a void-which-binds handoff. */
    fun parseOrNull(uri: String): Parsed? = try {
        parse(uri)
    } catch (_: Throwable) {
        null
    }

    /**
     * An **action-approval** link (void-which-binds-go ADR-0019): the same exact
     * `void-which-binds:approve?h=<handle>` tuple a wake carries, opened under the one
     * `void-which-binds:` filter. It takes no `callback` and nothing else — any other
     * spelling is refused ([Approval.parseApprove] is an exact match, not a URI parse),
     * so this returns null for it, and for a login or pair link (use [parseOrNull]).
     */
    fun parseApproveOrNull(uri: String): Handle? = Approval.parseApproveOrNull(uri)

    /**
     * Whether [callback] is a URI the authenticator will launch after approval: a
     * private app scheme (`scheme:` per RFC 3986 — a letter, then letters/digits/`+.-`),
     * NOT a web/system scheme that could open a browser, a file, a content provider
     * or an arbitrary `intent:`, not `void-which-binds:` (no re-entry loops), no whitespace or
     * control characters, and at most [MAX_CALLBACK_LENGTH] characters.
     */
    fun isWellFormedCallback(callback: String): Boolean {
        if (callback.isEmpty() || callback.length > MAX_CALLBACK_LENGTH) return false
        if (callback.any { it <= ' ' || it.code == 0x7f }) return false
        val colon = callback.indexOf(':')
        if (colon <= 0) return false
        val scheme = callback.substring(0, colon)
        if (!scheme[0].isAsciiLetter()) return false
        if (!scheme.all { it.isAsciiLetter() || it in '0'..'9' || it == '+' || it == '-' || it == '.' }) return false
        return scheme.lowercase() !in DENIED_SCHEMES
    }

    private val DENIED_SCHEMES = setOf(
        LoginQr.SCHEME, "http", "https", "javascript", "file", "content", "intent",
        "android-app", "data", "about", "blob", "ftp", "tel", "sms", "mailto",
    )

    private fun Char.isAsciiLetter() = this in 'A'..'Z' || this in 'a'..'z'

    private fun withCallback(tuple: String, callback: String?): String {
        if (callback == null) return tuple
        require(isWellFormedCallback(callback)) { "callback is not a well-formed private app-scheme URI" }
        return "$tuple&$CALLBACK=${UrlQuery.escape(callback)}"
    }

    /** The validated `callback` of a `void-which-binds:<kind>?<query>` URI, or null. */
    private fun callbackOf(uri: String): String? {
        val q = uri.indexOf('?')
        if (q < 0) return null
        val raw = try {
            UrlQuery.decode(uri.substring(q + 1))[CALLBACK]
        } catch (_: Throwable) {
            null
        } ?: return null
        return raw.takeIf { isWellFormedCallback(it) }
    }
}
