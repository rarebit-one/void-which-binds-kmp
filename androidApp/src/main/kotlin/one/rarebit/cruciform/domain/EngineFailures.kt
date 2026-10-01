package one.rarebit.cruciform.domain

import one.rarebit.voidwhichbinds.RecoverySecret
import one.rarebit.voidwhichbinds.flow.PairingFailureKind
import one.rarebit.voidwhichbinds.flow.PairingOutcome

/**
 * A gen1 (`heyarr1…`) recovery secret, typed or scanned. Gen2 has no gen1 reader
 * (void-which-binds-go ADR-0022): the library throws
 * [one.rarebit.voidwhichbinds.RecoverySecret.GenerationRetiredException] and the app
 * says plainly why, rather than calling the old sheet a typo.
 */
const val RETIRED_RECOVERY_SHEET =
    "This is an old (gen1) recovery sheet. It was retired at the Void-Which-Binds cutover " +
        "and can't restore or check an identity. Use your new sheet: its secret starts void-which-binds1."

/** [RETIRED_RECOVERY_SHEET] as a failure: a deliberate refusal, resolved by the gen2 sheet. */
internal val RETIRED_RECOVERY_FAILURE =
    EngineFailure(RETIRED_RECOVERY_SHEET, EngineFailure.Kind.NOT_YET, retryable = false)

/**
 * Classify a scanned string that is not a login or pairing code: a recovery sheet's
 * secret, a gen1 (`heyarr1…`) sheet — recognised only to say it was retired — or junk.
 */
internal fun scannedRecoverySecret(raw: String): ScannedCode =
    when (runCatching { RecoverySecret.parse(raw) }.exceptionOrNull()) {
        null -> ScannedCode.RecoverySecret(raw)
        is RecoverySecret.GenerationRetiredException -> ScannedCode.RetiredRecoverySecret(raw)
        else -> ScannedCode.Unknown(raw)
    }

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
