package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.approval.Approval
import one.rarebit.voidwhichbinds.approval.Handle

/**
 * The device side of the **push/wake ping** (void-which-binds-go `notify.Ping`). When a
 * push login is initiated, the notify plane fans an OPAQUE ping to a user's
 * subscribed devices over their wake channel (self-hosted ntfy / UnifiedPush). This
 * is the pure parser the Android push receiver calls on the delivered bytes — kept
 * in `commonMain` so it is unit-tested without an Android runtime.
 *
 * # The load-bearing invariant: the ping is a wake signal, not a crypto path
 *
 * The ping carries ONLY the public login tuple — `void-which-binds:login?rp=<>&id=<>` — the
 * exact same string a QR encodes (void-which-binds-go builds both with the same encoder).
 * It holds no challenge, no nonce, no cert, no key material, and — for a
 * number-matching login — **no match number**. So this parser deliberately does no
 * more than [VoidbindQr.parse]: it turns the woken bytes into the same
 * `(rp, id)` a scan would, and the phone then PULLS the real challenge from the RP
 * over TLS and signs it hardware-gated. A parser that expected a secret in the ping
 * would be a design error — there is none to expect, and [parse] never reads one.
 *
 * A malformed or non-void-which-binds body is rejected (thrown), so a stray push cannot
 * drive the app anywhere; the receiver simply ignores what does not parse.
 */
object PushPing {

    /**
     * Parse a delivered wake payload into the login (or pairing) it points at. The
     * body IS the opaque tuple (void-which-binds-go publishes `ping.Tuple` as the raw ntfy
     * message body), so this trims surrounding whitespace and defers entirely to
     * [VoidbindQr.parse]. It reads nothing but the tuple — there is no secret in the
     * ping to read. Throws on anything that is not a void-which-binds tuple.
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

    /**
     * Parse a delivered wake payload as an **action-approval** wake (void-which-binds-go
     * ADR-0019): `void-which-binds:approve?h=<handle>`, which carries only an opaque
     * [Handle] — no rp, no challenge id, nothing about the action. The approver then
     * fetches the action from the broker it holds standing at
     * ([one.rarebit.voidwhichbinds.net.ApprovalClient]), proving a member key. Unlike
     * [parse], nothing is trimmed: the notify plane's wire bytes ARE the tuple, and
     * [Approval.parseApprove] is an exact match. Null for anything else (a login ping
     * included — try [parseOrNull] for those).
     */
    fun parseApproveOrNull(rawBody: String): Handle? = Approval.parseApproveOrNull(rawBody)
}
