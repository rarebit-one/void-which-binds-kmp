package one.rarebit.cruciform.domain

import one.rarebit.voidwhichbinds.flow.PairingFailureKind
import one.rarebit.voidwhichbinds.flow.PairingOutcome

/** A declined or dismissed prompt. */
internal val CANCELLED_FAILURE =
    EngineFailure("Authentication cancelled.", EngineFailure.Kind.CANCELLED, retryable = false)

internal fun <T> internalFailure(message: String): EngineResult<T> {
    val failure = EngineFailure(message, EngineFailure.Kind.INTERNAL, retryable = false)
    return EngineResult.Failed(failure)
}

/**
 * A deliberate refusal the user can resolve ([EngineFailure.Kind.NOT_YET]): the app
 * titles it "Not yet", not "Something went wrong", and [message] says what to do.
 */
internal fun <T> notYetFailure(message: String): EngineResult<T> {
    val failure = EngineFailure(message, EngineFailure.Kind.NOT_YET, retryable = false)
    return EngineResult.Failed(failure)
}

internal fun <T> cancelledFailure(): EngineResult<T> = EngineResult.Failed(CANCELLED_FAILURE)

/**
 * A destructive/authority act asked for a strong biometric and this device has
 * none enrolled. We deliberately do NOT fall back to the screen-lock credential
 * (that is the exact hole strong-only closes), so the honest answer is to point
 * the user at recovery. Not retryable — retrying without enrolling a biometric
 * hits the same wall.
 *
 * [EngineFailure.Kind.NOT_YET], like the other refusals: nothing went wrong, the
 * device lacks what the act needs, and the message names the ways forward.
 */
internal fun <T> strongBiometricRequiredFailure(): EngineResult<T> = EngineResult.Failed(
    EngineFailure(
        "This needs a fingerprint or face unlock — your PIN can't authorise it. " +
            "Enrol a biometric on this device, or use another device or your recovery secret.",
        EngineFailure.Kind.NOT_YET,
        retryable = false,
    ),
)

/** A classified pairing failure from the library, as the app shows it. */
internal fun PairingOutcome.Failed.toEngineFailure(): EngineFailure = EngineFailure(
    message = message,
    kind = when (kind) {
        PairingFailureKind.UNREACHABLE -> EngineFailure.Kind.UNREACHABLE
        PairingFailureKind.TIMEOUT -> EngineFailure.Kind.TIMEOUT
        PairingFailureKind.REJECTED -> EngineFailure.Kind.REJECTED
        PairingFailureKind.PROTOCOL -> EngineFailure.Kind.PROTOCOL
        PairingFailureKind.REFUSED -> EngineFailure.Kind.REJECTED // declined (ADR-0012): the message says so
    },
    // Unreachable: retry the same step once the network is back. Timeout/rejected:
    // a fresh invite is needed, so the UI's retry re-mints/re-scans (still "retryable"
    // from the human's point of view). Protocol: never against the same session.
    retryable = kind != PairingFailureKind.PROTOCOL,
)
