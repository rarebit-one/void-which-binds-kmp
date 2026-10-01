package one.rarebit.cruciform.handoff

import one.rarebit.voidwhichbinds.VoidbindDeepLink

/**
 * A login/pairing the app was WOKEN into from outside its own UI — by a push ping
 * ([Origin.PUSH]) or by another app's `void-which-binds:` deep link ([Origin.DEEP_LINK], the
 * same-device app-to-app handoff). The nav graph runs the identical approval flow a
 * scan does; the origin only decides what happens AFTER the human decides:
 *
 * - **PUSH** — stay in the authenticator (go Home), as before.
 * - **DEEP_LINK** — finish the activity so the calling app resumes (it is polling
 *   its broker for the outcome), and — only after a successful approval, and only if
 *   the RP supplied a well-formed private-scheme [callback] — launch that callback
 *   bare, so the RP can foreground itself. Nothing about the login (no id, no
 *   challenge, no signature) is ever appended to it.
 *
 * [seq] makes two identical wakes distinct so the second one re-fires the flow.
 */
data class Handoff(
    val kind: Kind,
    val origin: Origin,
    /** The bare `void-which-binds:` tuple (no callback) — exactly what a scan would yield. */
    val tuple: String,
    val callback: String?,
    val seq: Int,
) {
    enum class Kind { LOGIN, PAIR }
    enum class Origin { PUSH, DEEP_LINK }

    /** True when the activity should finish (and possibly launch [callback]) once decided. */
    val returnsToCaller: Boolean get() = origin == Origin.DEEP_LINK
}

/**
 * Turns an incoming intent into a [Handoff] — pure Kotlin over the intent's
 * `action` + `dataString` so it is unit-tested without an Android runtime. The URI
 * is untrusted input from another app: everything goes through
 * [VoidbindDeepLink.parse] (as strict as a scan), a bad callback is dropped there,
 * and anything that is not a `void-which-binds:` login/pair VIEW yields null — the
 * retired gen1 `voidbind:` scheme included (void-which-binds-go ADR-0022: no gen1 reader).
 */
object HandoffRouter {

    /** `Intent.ACTION_VIEW`, as a string so this file stays free of android.* imports. */
    const val ACTION_VIEW = "android.intent.action.VIEW"

    /** The one scheme this app answers (the manifest registers it alone). */
    private const val SCHEME_PREFIX = "void-which-binds:"

    fun fromDeepLink(action: String?, dataString: String?, seq: Int): Handoff? {
        if (action != ACTION_VIEW) return null
        val uri = dataString?.trim() ?: return null
        if (!uri.startsWith(SCHEME_PREFIX, ignoreCase = false)) return null
        return when (val parsed = VoidbindDeepLink.parseOrNull(uri)) {
            is VoidbindDeepLink.Parsed.Login ->
                Handoff(Handoff.Kind.LOGIN, Handoff.Origin.DEEP_LINK, parsed.tuple, parsed.callback, seq)

            is VoidbindDeepLink.Parsed.Pair ->
                Handoff(Handoff.Kind.PAIR, Handoff.Origin.DEEP_LINK, parsed.tuple, parsed.callback, seq)

            null -> null
        }
    }

    /** A push wake: the receiver already reduced the ping to the opaque login tuple. */
    fun fromPush(tuple: String?, seq: Int): Handoff? {
        val t = tuple?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return Handoff(Handoff.Kind.LOGIN, Handoff.Origin.PUSH, t, callback = null, seq = seq)
    }
}
