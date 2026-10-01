package one.rarebit.cruciform.ui.nav

import one.rarebit.cruciform.domain.RETIRED_RECOVERY_SHEET
import one.rarebit.cruciform.domain.ScannedCode

/** What a scanner is open for. */
enum class ScanMode {
    /** The bottom-bar / onboarding scanner: any Void-Which-Binds code, or a recovery sheet. */
    ANY,

    /** Opened from the Restore or drill field: only a recovery secret, handed back to it. */
    RECOVERY_SECRET,
}

/** What the graph does with one scanned code. Secrets never appear in [toString]. */
sealed interface ScanAction {
    data class OpenLogin(val code: ScannedCode.WebLogin) : ScanAction

    data class JoinPair(val code: ScannedCode.PairInvite) : ScanAction

    /** No identity here yet: restore from the scanned secret. */
    data class Restore(val secret: String) : ScanAction {
        override fun toString(): String = "Restore(<redacted>)"
    }

    /** An identity is here: check the scanned secret against it (the drill). */
    data class Drill(val secret: String) : ScanAction {
        override fun toString(): String = "Drill(<redacted>)"
    }

    /** Hand the secret back to the field that opened the scanner. */
    data class ReturnSecret(val secret: String) : ScanAction {
        override fun toString(): String = "ReturnSecret(<redacted>)"
    }

    /** Not what this scanner reads: say so and let the user scan again. */
    data class Reject(val message: String) : ScanAction
}

const val NOT_A_VOID_WHICH_BINDS_CODE = "Not a Void-Which-Binds code"
const val NOT_A_RECOVERY_SECRET = "Not a recovery secret. Scan the QR code on your printed recovery sheet."

/**
 * Route a scanned [code]. Login and pairing codes keep their meaning in the general
 * scanner; a recovery sheet restores ([hasIdentity] false) or runs the drill (true).
 * A scanner opened for a recovery secret takes nothing else.
 */
fun scanAction(code: ScannedCode, mode: ScanMode, hasIdentity: Boolean): ScanAction = when (mode) {
    ScanMode.RECOVERY_SECRET -> when (code) {
        is ScannedCode.RecoverySecret -> ScanAction.ReturnSecret(code.raw)
        is ScannedCode.RetiredRecoverySecret -> ScanAction.Reject(RETIRED_RECOVERY_SHEET)
        else -> ScanAction.Reject(NOT_A_RECOVERY_SECRET)
    }

    ScanMode.ANY -> when (code) {
        is ScannedCode.WebLogin -> ScanAction.OpenLogin(code)
        is ScannedCode.PairInvite -> ScanAction.JoinPair(code)
        is ScannedCode.RecoverySecret -> if (hasIdentity) ScanAction.Drill(code.raw) else ScanAction.Restore(code.raw)
        is ScannedCode.RetiredRecoverySecret -> ScanAction.Reject(RETIRED_RECOVERY_SHEET)
        is ScannedCode.Unknown -> ScanAction.Reject(NOT_A_VOID_WHICH_BINDS_CODE)
    }
}
