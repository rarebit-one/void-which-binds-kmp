package one.rarebit.voidwhichbinds

/**
 * The device side of the **push/wake ping** (void-which-binds-go `notify.Ping`). When a
 * push login is initiated, the notify plane fans an OPAQUE ping to a user's
 * subscribed devices over their wake channel (self-hosted ntfy / UnifiedPush). This
 * is the pure parser the Android push receiver calls on the delivered bytes — kept
 * in `commonMain` so it is unit-tested without an Android runtime.
 *
 * # The load-bearing invariant: the ping is a wake signal, not a crypto path
 *
 * The ping carries ONLY the public login tuple — `voidbind:login?rp=<>&id=<>` — the
 * exact same string a QR encodes (void-which-binds-go builds both with the same encoder).
 * It holds no challenge, no nonce, no cert, no key material, and — for a
 * number-matching login — **no match number**. So this parser deliberately does no
 * more than [VoidbindQr.parse]: it turns the woken bytes into the same
 * `(rp, id)` a scan would, and the phone then PULLS the real challenge from the RP
 * over TLS and signs it hardware-gated. A parser that expected a secret in the ping
 * would be a design error — there is none to expect, and [parse] never reads one.
 *
 * A malformed or non-voidbind body is rejected (thrown), so a stray push cannot
 * drive the app anywhere; the receiver simply ignores what does not parse.
 */
object PushPing {

    /**
     * Parse a delivered wake payload into the login (or pairing) it points at. The
     * body IS the opaque tuple (void-which-binds-go publishes `ping.Tuple` as the raw ntfy
     * message body), so this trims surrounding whitespace and defers entirely to
     * [VoidbindQr.parse]. It reads nothing but the tuple — there is no secret in the
     * ping to read. Throws on anything that is not a voidbind tuple.
     */
    @Throws(Exception::class)
    fun parse(rawBody: String): VoidbindQr = VoidbindQr.parse(rawBody.trim())

    /**
     * A non-throwing variant for a receiver that wants to silently drop a stray or
     * malformed push rather than surface an error: returns null instead of throwing.
     */
    fun parseOrNull(rawBody: String): VoidbindQr? = try {
        parse(rawBody)
    } catch (_: Throwable) {
        null
    }
}
