package one.rarebit.cruciform.handoff

/**
 * The **same-phone one-tap** channel (ADR-0008): the relying-party app this phone just
 * handed an invite to reports, over a LOCAL intent the relay cannot touch, the two
 * values a human would otherwise have compared by eye —
 *
 *     cruciform://pair-joined?session=<relay session>&dev=<its ed25519:… device key>&sas=<its SAS>
 *
 * — so the SAS check is satisfied by the *apps*, not by the person holding the phone.
 * The intent is not a new authority: it is a SECOND channel. Cruciform still runs the
 * full commit-before-reveal handshake over the relay and still derives its own SAS and
 * learns the responder's device key from the relay reveal; this callback is only
 * compared against that. A relay man-in-the-middle would substitute its own key on the
 * relay channel and could not forge the app's local report, so the comparison fails and
 * nothing is signed — which is exactly what the human comparison bought us on two
 * devices. Cross-device pairing has no such channel and keeps the human SAS.
 *
 * Nothing here trusts the caller: the values are compared, never adopted. Pure Kotlin
 * (no `android.*`) so every decision below is unit-tested on the JVM.
 */
sealed interface SamePhonePairCallback {

    /** A well-formed report from an RP on this phone. */
    data class Joined(
        /** The relay session the RP says it joined. */
        val session: String,
        /** The RP's device signing key, `ed25519:<hex>` as it renders it. */
        val dev: String,
        /** The RP's SAS, however it formats it (digits are compared, not the spacing). */
        val sas: String,
    ) : SamePhonePairCallback

    /** Ours (`cruciform://pair-joined…`) but unusable; [message] says why, for a log. */
    data class Malformed(val message: String) : SamePhonePairCallback

    /**
     * What Cruciform does with a [Joined] report, decided against what the RELAY
     * revealed for the same session.
     */
    sealed interface Decision {
        /**
         * Both the device key and the SAS agree with the relay: the two apps have
         * checked each other and the human is asked ONE question ("allow this app to
         * act as you?") behind the biometric, with no code to compare.
         */
        data object Match : Decision

        /**
         * The report is for a session this device is not running. Ignore it — a stale
         * callback from an abandoned invite, or a second app being noisy. Not an
         * attack signal, and never a reason to touch the live invite.
         */
        data class OtherSession(val reason: String) : Decision

        /**
         * The invite is live but the handshake has not revealed the peer yet (the RP
         * beat us to it). Hold the report and re-decide when the relay reveal lands —
         * never a reason to sign, never a reason to refuse.
         */
        data object TooEarly : Decision

        /**
         * The local report and the relay disagree. On one phone the only way to get
         * here is a relay that substituted a key — refuse loudly and sign NOTHING.
         */
        data class Mismatch(val reason: String) : Decision
    }

    companion object {
        const val ACTION_VIEW = "android.intent.action.VIEW"
        const val SCHEME = "cruciform"
        const val HOST = "pair-joined"

        const val PARAM_SESSION = "session"
        const val PARAM_DEV = "dev"
        const val PARAM_SAS = "sas"

        /** The RP's own "you're enrolled, come back" landing: `<rp scheme>://pair-done?session=…`. */
        const val DONE_HOST = "pair-done"

        /** Query keys on the return leg beyond the session: only set when the pairing was refused. */
        const val PARAM_OUTCOME = "outcome"
        const val PARAM_REASON = "reason"
        const val OUTCOME_REFUSED = "refused"

        private const val PREFIX = "$SCHEME://$HOST"

        /**
         * Route an incoming intent. Null when it is not a `cruciform://pair-joined` VIEW
         * at all (a launcher start, a `void-which-binds:` handoff, anything else) so the caller
         * ignores it; [Malformed] when it is ours but unusable.
         */
        fun route(action: String?, dataString: String?): SamePhonePairCallback? {
            if (action != ACTION_VIEW) return null
            val uri = dataString?.trim() ?: return null
            if (!uri.startsWith(PREFIX)) return null
            val rest = uri.substring(PREFIX.length)
            // `…//pair-joined`, `…/`, `…?…` — nothing else (e.g. `pair-joined-x`) is ours.
            if (rest.isNotEmpty() && rest[0] != '?' && rest[0] != '/') return null
            val q = rest.indexOf('?')
            val query = if (q < 0) "" else rest.substring(q + 1)
            val session = param(query, PARAM_SESSION) ?: return Malformed("no session in the callback")
            val dev = param(query, PARAM_DEV) ?: return Malformed("no device key in the callback")
            val sas = param(query, PARAM_SAS) ?: return Malformed("no security code in the callback")
            if (session.isEmpty() || dev.isEmpty() || sas.isEmpty()) return Malformed("an empty value in the callback")
            return Joined(session, dev, sas)
        }

        /**
         * Decide what [report] means for the invite this device is running.
         *
         * [liveSession] is the relay session of the live invite (null when there is no
         * invite at all); [revealedDev] / [revealedSas] are what the RELAY handshake
         * produced, both null until it completes.
         *
         * The comparison is deliberately narrow: a key must match exactly once
         * case-folded (both sides render `ed25519:<lowercase hex>`), and a SAS matches
         * on its DIGITS only — Cruciform groups it `NNN NNNN` for the eye and an RP may
         * not, and the digits are the whole of the value.
         */
        fun decide(report: Joined, liveSession: String?, revealedDev: String?, revealedSas: String?): Decision {
            if (liveSession.isNullOrEmpty()) {
                return Decision.OtherSession("no invite is live on this device")
            }
            if (!report.session.equals(liveSession, ignoreCase = true)) {
                return Decision.OtherSession(
                    "the callback names session ${report.session}, this device is running $liveSession",
                )
            }
            if (revealedDev.isNullOrEmpty() || revealedSas.isNullOrEmpty()) return Decision.TooEarly
            if (!report.dev.trim().equals(revealedDev.trim(), ignoreCase = true)) {
                return Decision.Mismatch(
                    "The app on this phone reports a different device key from the one the relay revealed. " +
                        "That can only happen if the pairing is being intercepted — nothing was signed.",
                )
            }
            if (digits(report.sas) != digits(revealedSas)) {
                return Decision.Mismatch(
                    "The app on this phone reports a different security code from the one this device derived. " +
                        "That can only happen if the pairing is being intercepted — nothing was signed.",
                )
            }
            if (digits(revealedSas).isEmpty()) {
                return Decision.Mismatch("The security code is empty — nothing was signed.")
            }
            return Decision.Match
        }

        /**
         * Where to send the human back to once the add is signed: the RP's own
         * `<scheme>://pair-done?session=<id>` landing. Cruciform launches it bare —
         * the session id only, so the RP can match it to the pairing it is waiting on.
         * Nothing about the admission travels here; the RP already received it, sealed,
         * over the relay.
         */
        fun doneUri(rpScheme: String, session: String, outcome: String? = null, reason: String? = null): String {
            require(rpScheme.isNotBlank()) { "no RP scheme" }
            return buildString {
                append(rpScheme).append("://").append(DONE_HOST).append('?').append(PARAM_SESSION).append('=')
                append(RpPairHandoff.percentEncode(session))
                if (outcome !=
                    null
                ) {
                    append('&').append(PARAM_OUTCOME).append('=').append(RpPairHandoff.percentEncode(outcome))
                }
                if (reason !=
                    null
                ) {
                    append('&').append(PARAM_REASON).append('=').append(RpPairHandoff.percentEncode(reason))
                }
            }
        }

        /**
         * The RP's landing with a verdict it would otherwise never learn: the one-tap
         * report DISAGREED with what the relay revealed, so Cruciform refused and signed
         * nothing. Without this leg the RP waits on "Approve in Cruciform" until its
         * relay session expires. `reason` is Cruciform's own wording, verbatim.
         */
        fun refusedUri(rpScheme: String, session: String, reason: String): String =
            doneUri(rpScheme, session, OUTCOME_REFUSED, reason)

        /** Digits only — the SAS's actual value, free of whatever grouping a screen used. */
        internal fun digits(s: String): String = s.filter { it in '0'..'9' }

        /** First value of [key] in a `k=v&k=v` query, percent-decoded, or null when absent. */
        private fun param(query: String, key: String): String? {
            if (query.isEmpty()) return null
            for (pair in query.split('&')) {
                val eq = pair.indexOf('=')
                val k = if (eq < 0) pair else pair.substring(0, eq)
                if (k != key) continue
                val raw = if (eq < 0) "" else pair.substring(eq + 1)
                return try {
                    percentDecode(raw)
                } catch (e: IllegalArgumentException) {
                    null
                }
            }
            return null
        }

        /**
         * RFC 3986 percent-decoding (`%XX` → byte, UTF-8). A `+` is left alone: the
         * sender writes a space as `%20`, and none of these values contains one.
         */
        internal fun percentDecode(s: String): String {
            val out = ByteArray(s.length)
            var n = 0
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%') {
                    require(i + 2 < s.length) { "truncated percent-escape" }
                    out[n++] = ((hexVal(s[i + 1]) shl 4) or hexVal(s[i + 2])).toByte()
                    i += 3
                } else {
                    require(c.code < 0x80) { "non-ASCII character in the callback" }
                    out[n++] = c.code.toByte()
                    i++
                }
            }
            return out.copyOf(n).decodeToString()
        }

        private fun hexVal(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            in 'A'..'F' -> c - 'A' + 10
            else -> throw IllegalArgumentException("bad percent-escape digit '$c'")
        }
    }
}
