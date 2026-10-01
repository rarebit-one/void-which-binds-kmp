package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.WebLogin
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.WebLoginClient
import one.rarebit.voidwhichbinds.net.WebLoginHttpException

/**
 * The device side of **web QR-login** as one app flow: the user scans a
 * `voidbind:login?rp=&id=` QR on a browser, the app shows WHAT they are signing
 * into, and — only after the human taps Approve — the device signs the RP's
 * challenge with its hardware key and submits the assertion. The RP then verifies
 * it offline against the pinned user key and mints a short-lived session token.
 *
 * Two steps so the biometric prompt lands at the human's decision, not at scan:
 *  1. [begin] decodes the QR and FETCHES the challenge from the RP (the RP is the
 *     source of truth for what is signed) → a [Request] the approval sheet shows.
 *  2. [approve] signs the exact fetched challenge and POSTs the assertion.
 *
 * Blocking (network); run it off the main thread. Wraps [WebLoginClient] +
 * [WebLogin.signAssertion] — every signed byte is byte-identical to void-which-binds-go.
 */
class LoginApproval(
    private val http: HttpTransport,
    private val device: DeviceIdentity,
    /** This device's admitting op (or v1/v2 cert) token; the signing key MUST be the one it names. */
    private val enrolmentCert: String,
    /**
     * The membership ops this device knows (ADR-0005) — presented beside the
     * credential so an RP that has never met the member that admitted this device
     * can evaluate the admission. Empty for a genesis-admitted device on an RP that
     * pinned the identity (the cert alone is the whole proof).
     */
    private val knownOps: List<String> = emptyList(),
) {
    /**
     * What the approval sheet shows the human. [audience] is the RP origin the
     * challenge binds; [expiresAt] is unix seconds (render a live countdown).
     *
     * [candidates] is non-empty only for a **number-matching (v2)** login (a push
     * wake, where nothing was scanned): the approval UI shows these numbers and the
     * user taps the one matching the initiating surface. The true match is not here —
     * only the RP holds it — so the tap, not the fetch, is what proves the human is
     * looking at the right screen. Approve such a request with [approve] passing the
     * chosen number; a v1 request uses the no-argument-number overload.
     */
    class Request internal constructor(
        val rp: String,
        val loginId: String,
        val audience: String,
        val expiresAt: Long,
        val candidates: List<Int>,
        internal val challenge: WebLogin.Challenge,
    ) {
        /** True for a v2 (number-matching) login — the UI must show [candidates] and take a tap. */
        val isNumberMatch: Boolean get() = candidates.isNotEmpty()
    }

    /** Why a [begin] failed, kept coarse on purpose (see [Outcome.Failed]). */
    enum class FailureKind {
        /** The RP could not be reached at all — connection refused, TLS error, timeout, a
         *  cleartext-blocked URL. The device never got a response. */
        UNREACHABLE,

        /** The RP was reached and answered, but the login-challenge is gone: a `404 Not Found`
         *  (or `410 Gone`) on the fetch. weblogin login ids are short-lived, so this means the
         *  scanned code EXPIRED or was lost (e.g. the RP restarted) — NOT a deliberate refusal.
         *  The fix is to scan a fresh QR, so it gets its own message, distinct from [REJECTED]. */
        EXPIRED,

        /** The RP was reached but genuinely refused the challenge fetch — any other non-2xx
         *  status (a 4xx that is not 404/410, or a 5xx). */
        REJECTED,
    }

    /**
     * The result of a non-throwing [beginCatching]: either the [Request] to show, or a
     * classified [Failed] the UI can render as a login error instead of crashing.
     */
    sealed interface Outcome {
        data class Ready(val request: Request) : Outcome
        data class Failed(val kind: FailureKind, val message: String) : Outcome
    }

    /**
     * Like [begin], but a transport/IO failure or a non-2xx from the RP resolves to an
     * [Outcome.Failed] the caller can render — it never throws for a fetch failure. This
     * is the boundary that keeps a failed login-challenge fetch (an unreachable RP, a TLS
     * error, a timeout, a 4xx/5xx, a cleartext-blocked URL) from becoming an uncaught
     * crash. The throwing [begin] overloads remain for callers (e.g. iOS) that already
     * catch. Blocking (network); run it off the main thread.
     */
    fun beginCatching(loginQr: String): Outcome = beginCatching(LoginQr.decode(loginQr))

    /** [beginCatching] for an already-parsed QR (the Scan screen path). */
    fun beginCatching(parsed: LoginQr.Parsed): Outcome = try {
        Outcome.Ready(begin(parsed))
    } catch (e: WebLoginHttpException) {
        // A 404 (or 410 Gone) on the challenge fetch means the short-lived login id expired or was
        // lost (the RP restarted) — a stale code, not a refusal — so it gets its own EXPIRED kind
        // with a "scan a fresh QR" message. Every other non-2xx is a genuine refusal (REJECTED).
        if (e.status == 404 || e.status == 410) {
            Outcome.Failed(FailureKind.EXPIRED, "This sign-in code has expired — scan a fresh QR.")
        } else {
            Outcome.Failed(FailureKind.REJECTED, "The site refused the sign-in request (HTTP ${e.status}).")
        }
    } catch (_: Throwable) {
        // Any other failure is a transport/IO problem (unreachable, TLS, timeout,
        // cleartext-blocked) or a malformed response — from the human's point of view the
        // site could not be reached. Deliberately does not leak the raw exception text.
        Outcome.Failed(FailureKind.UNREACHABLE, "Couldn't reach the site.")
    }

    /** Decode a scanned login QR, fetch the challenge, and return what to show. */
    @Throws(Exception::class)
    fun begin(loginQr: String): Request = begin(LoginQr.decode(loginQr))

    /** Same, when the Scan screen already parsed the QR via [one.rarebit.voidwhichbinds.VoidbindQr]. */
    @Throws(Exception::class)
    fun begin(parsed: LoginQr.Parsed): Request {
        val client = WebLoginClient(http, parsed.rp)
        val challenge = client.fetchChallenge(parsed.id)
        return Request(
            parsed.rp,
            parsed.id,
            challenge.audience,
            challenge.expiresAt,
            challenge.candidates,
            challenge,
        )
    }

    /**
     * After the human confirms: sign the fetched challenge with the device key
     * (biometric-gated inside [DeviceIdentity.sign]) and submit the assertion.
     * Throws if the RP refuses it (expired, unpinned device, replay). `@Throws` so
     * the refusal is catchable in Swift (a retry prompt), not a crash.
     *
     * v1 only — a scanned QR carries its origin-binding already. For a
     * number-matching (v2) request ([Request.isNumberMatch]) use the [approve]
     * overload that takes the chosen number.
     */
    @Throws(Exception::class)
    fun approve(request: Request) {
        require(!request.isNumberMatch) {
            "this is a number-matching login — approve(request, chosenNumber)"
        }
        val assertion = WebLogin.signAssertion(request.challenge, enrolmentCert, ops = knownOps) { message ->
            device.sign(message)
        }
        WebLoginClient(http, request.rp).approve(request.loginId, assertion)
    }

    /**
     * Approve a **number-matching (v2)** login: sign the challenge bound to the
     * [chosenNumber] the human tapped (biometric-gated) and submit it. [chosenNumber]
     * must be one of [Request.candidates]. If the human tapped a decoy, the signature
     * binds the wrong number and the RP refuses it (its `ErrNumberMismatch` → a 401
     * that surfaces here as a thrown refusal) — so a wrong tap yields no login, which
     * is the whole anti-phishing point.
     */
    @Throws(Exception::class)
    fun approve(request: Request, chosenNumber: Int) {
        require(request.isNumberMatch) { "this is not a number-matching login — use approve(request)" }
        require(chosenNumber in request.candidates) {
            "chosen number $chosenNumber is not one of the candidates shown"
        }
        val assertion = WebLogin.signAssertionV2(
            request.challenge,
            chosenNumber,
            enrolmentCert,
            ops = knownOps,
        ) { message ->
            device.sign(message)
        }
        WebLoginClient(http, request.rp).approve(request.loginId, assertion)
    }
}
