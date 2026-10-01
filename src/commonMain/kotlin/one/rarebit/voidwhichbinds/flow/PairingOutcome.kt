package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.PairingRefusedException
import one.rarebit.voidwhichbinds.net.RelayHttpException
import one.rarebit.voidwhichbinds.net.RelayTimeout

/**
 * Why a pairing step failed, kept coarse on purpose (the UI picks a title and a
 * retry affordance from it; the message already says what to do).
 */
enum class PairingFailureKind {
    /** The relay could not be reached at all — no route, connection refused, TLS error,
     *  timeout, a cleartext-blocked URL. The device never got a response. Retry once the
     *  network is back (Wi-Fi / VPN). */
    UNREACHABLE,

    /** The relay was reached, but the peer never showed up in its slot before the poll
     *  gave up ([RelayTimeout]) — the invite expired unjoined, or the other device gave
     *  up. Retry = mint / scan a fresh invite. */
    TIMEOUT,

    /** The relay was reached and answered with a non-success status — a stale or
     *  already-used session (a 404 / 409 on a write-once slot), or a server error. */
    REJECTED,

    /** The bytes came back but the protocol did not hold: a commitment that does not
     *  open (a rushing attacker), a cert that does not verify or binds another device,
     *  or a malformed envelope. Do NOT retry the same session — start again. */
    PROTOCOL,

    /** The other device REFUSED the pairing: its human said the numbers did not match,
     *  or cancelled (void-which-binds-go ADR-0012). The refusal is signed by the key the SAS
     *  bound, so it really came from that device. Nothing was admitted. Retry = a fresh
     *  invite; if the numbers keep differing, suspect the network. */
    REFUSED,
}

/**
 * The result of a non-throwing pairing step (`DevicePairing.beginCatching`,
 * `DeviceAuthorization.inviteCatching`, …): either the step's value, or a classified
 * [Failed] the UI renders instead of the app crashing on an uncaught exception.
 *
 * This is the boundary that keeps a blocking relay call that blows up (the on-device
 * crash: `SocketTimeoutException` from the OkHttp transport with no route to the relay)
 * from escaping a coroutine — the throwing overloads remain for callers that catch.
 */
sealed interface PairingOutcome<out T> {
    data class Ready<T>(val value: T) : PairingOutcome<T>

    /**
     * [message] is already human-readable and says what to do; it never carries raw
     * exception text. [relayHost] is the `host[:port]` of the relay the step targeted,
     * for a UI that wants to show it separately.
     */
    data class Failed(val kind: PairingFailureKind, val message: String, val relayHost: String) :
        PairingOutcome<Nothing>
}

/** Classifies a thrown pairing-step failure into a [PairingOutcome.Failed]. */
object PairingFailures {

    /**
     * Run [step] and turn any throw into a [PairingOutcome.Failed] for the relay at
     * [relayBase]. A `Ready` carries the step's value.
     */
    inline fun <T> catching(relayBase: String, step: () -> T): PairingOutcome<T> = try {
        PairingOutcome.Ready(step())
    } catch (e: Throwable) {
        classify(e, relayBase)
    }

    fun classify(e: Throwable, relayBase: String): PairingOutcome.Failed {
        val host = hostOf(relayBase)
        return when (e) {
            is PairingRefusedException -> PairingOutcome.Failed(
                PairingFailureKind.REFUSED,
                "The other device declined this pairing. If the numbers didn't match, start again " +
                    "with a fresh invite; if they keep differing, something on the network may be interfering.",
                host,
            )

            is RelayTimeout -> PairingOutcome.Failed(
                PairingFailureKind.TIMEOUT,
                "The other device didn't join in time. Start the pairing again with a fresh invite.",
                host,
            )

            is RelayHttpException -> PairingOutcome.Failed(
                PairingFailureKind.REJECTED,
                if (e.status == 404 || e.status == 409 || e.status == 410) {
                    "This pairing invite is no longer valid (HTTP ${e.status}). Start again with a fresh invite."
                } else {
                    "The relay at $host refused the request (HTTP ${e.status}). Try again."
                },
                host,
            )

            // The pairflow / cert layers signal a protocol violation with require()/check()
            // (IllegalArgument/IllegalState) and a malformed envelope with a parse error
            // (NumberFormat, ClassCast, IndexOutOfBounds…). None of these is a network
            // problem, so retrying the same session cannot help.
            is IllegalArgumentException, is IllegalStateException,
            is ClassCastException, is IndexOutOfBoundsException, is NumberFormatException,
            is NullPointerException,
            -> PairingOutcome.Failed(
                PairingFailureKind.PROTOCOL,
                "The pairing didn't verify — the other device may not be the one you expect. Start again.",
                host,
            )

            // Everything else reached this seam from the transport: no route, refused, TLS,
            // timeout, cleartext-blocked. From the human's point of view the relay is down or
            // unreachable from this network. Deliberately does not leak the exception text.
            else -> PairingOutcome.Failed(
                PairingFailureKind.UNREACHABLE,
                "Can't reach the relay at $host. Check Wi-Fi or your VPN and try again.",
                host,
            )
        }
    }

    /**
     * `host[:port]` of a URL, for a message (`http://192.168.16.224:7777/pair` →
     * `192.168.16.224:7777`). Pure string work — commonMain has no URI type. Falls back
     * to the input trimmed of its scheme when there is no recognisable authority.
     */
    fun hostOf(url: String): String {
        val trimmed = url.trim()
        val afterScheme = trimmed.substringAfter("://", missingDelimiterValue = trimmed)
        val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }
        val hostPort = authority.substringAfterLast('@')
        return hostPort.ifBlank { trimmed.ifBlank { "the relay" } }
    }
}
