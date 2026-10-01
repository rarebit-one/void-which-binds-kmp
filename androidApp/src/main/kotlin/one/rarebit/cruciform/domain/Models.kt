package one.rarebit.cruciform.domain

import one.rarebit.voidwhichbinds.policy.ApprovalAuditEntry
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy

/**
 * UI-facing domain models. These are the app's own view of identity state, kept
 * deliberately separate from the wire types in the KMP library so a screen never
 * touches raw key bytes — it renders a already-formatted [fingerprint] and a
 * boolean [hardwareBacked]. The real values are produced by a [VoidbindEngine];
 * the commonMain flow-coordinators (owned by the library side) are the source of
 * truth for anything cryptographic.
 */

/** A hardware-backing level, driving the "StrongBox / TEE / software" status copy. */
enum class HardwareBacking { STRONGBOX, TEE, SOFTWARE }

/** The signing identity as the UI shows it. */
data class Identity(
    /**
     * The human label shown beside the fingerprint: the name of THIS device as enrolled
     * (what the user chose in Settings, or the enrolled device name — never a placeholder
     * such as a mockup version tag). A paired "Add this device" install shows the name it
     * enrolled under; a device with no name shows `This device`.
     */
    val label: String,
    /** Space-grouped short fingerprint of the user identity key, e.g. `7C4A 91D2 0E8F`. */
    val fingerprint: String,
    /** Full `ed25519:<hex>` rendering, for copy. */
    val fullKey: String,
    val offlineVerifiable: Boolean = true,
)

/** This device's signing key + its secure-element status. */
data class DeviceInfo(
    val name: String,
    /** Role + short fingerprint, e.g. `dev · A29F 67B1`. */
    val label: String,
    val backing: HardwareBacking,
    val biometricRequired: Boolean,
) {
    val hardwareBacked: Boolean get() = backing != HardwareBacking.SOFTWARE
}

/**
 * One member of the identity's device set, as the Devices screen shows it — the
 * evaluated membership (`Membership.evaluate`, ADR-0005) projected to display fields.
 */
data class MemberDevice(
    /** The device signing key, `ed25519:<hex>` — what a remove op names. */
    val id: String,
    /** Short fingerprint, e.g. `A29F 67B1`. */
    val fingerprint: String,
    /** True for the device this app runs on (shown, but removed via a different path). */
    val isThisDevice: Boolean,
    /** Who admitted it: "genesis (recovery key)" or the admitting device's short fingerprint. */
    val admittedByLabel: String,
    /** Already-formatted admitted-at, e.g. "2 Sep 2026". */
    val admittedLabel: String,
    /** Already-formatted expiry, e.g. "renews by 1 Dec 2026". */
    val expiresLabel: String,
)

/** A relying party this identity has enrolled with. */
data class TrustedSite(
    val id: String,
    val domain: String,
    val appName: String,
    val lastUsed: String,
    /** A stable seed for the leading avatar's accent, 0..n. */
    val accent: SiteAccent = SiteAccent.BLUE,
    /**
     * This RP's per-site approval policy (trust-on-first-use vs. always-ask). Joined
     * in from the [one.rarebit.voidwhichbinds.policy.SitePolicyStore] at load time — it is
     * NOT part of the trusted-site serialization, so the two stores stay independent.
     */
    val policy: ApprovalPolicy = ApprovalPolicy.AlwaysAsk,
    /** True when the user pinned "always ask" — the toggle reflects an explicit choice, not a default. */
    val pinnedAlwaysAsk: Boolean = false,
)

enum class SiteAccent { BLUE, PURPLE, MINT }

/**
 * One row in the approval-activity log the UI renders — a UI projection of the
 * library's [ApprovalAuditEntry] with display-ready fields. The engine formats the
 * timestamp; the screen stays free of date math.
 */
data class ApprovalActivity(
    val rp: String,
    val audience: String,
    val loginId: String,
    val approved: Boolean,
    /** Already-formatted time, e.g. "just now" / "2h ago" / an absolute date. */
    val whenLabel: String,
    /** The tapped number for a number-matching (v2) login, or null for a scanned login. */
    val matchNumber: Int? = null,
) {
    companion object {
        fun from(entry: ApprovalAuditEntry, whenLabel: String): ApprovalActivity = ApprovalActivity(
            rp = entry.rp,
            audience = entry.audience,
            loginId = entry.loginId,
            approved = entry.decision == one.rarebit.voidwhichbinds.policy.ApprovalDecision.Approved,
            whenLabel = whenLabel,
            matchNumber = entry.matchNumber,
        )
    }
}

/** Overall identity state the app boots into. */
sealed interface IdentityState {
    /** No identity yet — the app shows onboarding. */
    data object None : IdentityState

    /** An identity is provisioned on this device. */
    data class Active(
        val identity: Identity,
        val device: DeviceInfo,
        val trustedSites: List<TrustedSite>,
        val biometricApproval: Boolean = true,
        /** This device keeps a (strong-biometric-sealed) copy of the recovery secret. */
        val holdsRecoverySecret: Boolean = false,
        val membership: MembershipHealth = MembershipHealth(),
        val backup: BackupStatus = BackupStatus(),
    ) : IdentityState

    /** Still loading from the keystore. */
    data object Loading : IdentityState
}

/** The newly minted recovery secret shown on the backup screen (create flow). */
data class RecoveryBackup(
    /** The bech32m secret, e.g. `heyarr1...`, already grouped for display. */
    val groupedSecret: String,
    /** The raw single-line secret, for copy. */
    val rawSecret: String,
    /** Whether this phone also keeps a copy; false means the written copy is the only one. */
    val keptOnDevice: Boolean = false,
    /** The identity's printable fingerprint (`XXXX XXXX XXXX XXXX`), printed on the sheet. */
    val fingerprint: String,
    /** The user identity `ed25519:<hex>` the secret restores, printed on the sheet. */
    val userId: String,
)

/**
 * Whether the identity's written recovery secret has been checked on this device.
 * Checking signs nothing: the secret is parsed, its identity derived and compared
 * (void-which-binds-go ADR-0010).
 */
data class BackupStatus(
    /** Created on this device and the written secret not yet confirmed: Home asks for it. */
    val confirmPending: Boolean = false,
    /** e.g. "Checked 25 Sep 2026"; null when never checked on this device. */
    val lastCheckedLabel: String? = null,
    /** The last check was more than a year ago: time for another drill. */
    val drillDue: Boolean = false,
)

/** A written recovery secret that matched this identity. */
data class RecoveryCheck(
    /** The identity's printable fingerprint (`XXXX XXXX XXXX XXXX`), to compare with paper. */
    val fingerprint: String,
)

/**
 * This device's standing in the identity's membership. An add lasts 90 days, and a
 * member renews itself before it lapses; a lapsed device can only be re-admitted.
 */
data class MembershipHealth(
    /** e.g. "renews by 1 Dec 2026"; null when this device is not a member. */
    val renewsByLabel: String? = null,
    /** Inside the renewal window — "Renew now" is offered. */
    val renewalDue: Boolean = false,
    /** No longer a member (its add lapsed, or it was removed). */
    val lapsed: Boolean = false,
)

/**
 * A decoded QR the scanner produced — a web-login request, a device pairing invite,
 * or the recovery secret printed on a recovery sheet. The library's `LoginQr` and
 * `RecoverySecret` parsers (commonMain) are the authority on the wire form; this is
 * the app's dispatch shape.
 */
sealed interface ScannedCode {
    data class WebLogin(val rpBase: String, val loginId: String, val raw: String) : ScannedCode
    data class PairInvite(val relay: String, val session: String, val raw: String) : ScannedCode

    /**
     * A recovery secret (`heyarr1…`, the sheet's QR carries it upper-case) that parsed,
     * checksum and all. [raw] is exactly what was scanned; it is only ever used to fill
     * the Restore or drill field, and [toString] never prints it.
     */
    data class RecoverySecret(val raw: String) : ScannedCode {
        override fun toString(): String = "RecoverySecret(<redacted>)"
    }

    data class Unknown(val raw: String) : ScannedCode
}

/** A pending web-login the user is being asked to approve. */
data class LoginRequest(
    val domain: String,
    val appName: String,
    val origin: String,
    val signInAs: String,
    val expiresInSeconds: Int,
    val access: String = "Authentication only",
    val signatureValid: Boolean = true,
    /**
     * Non-empty only for a **number-matching (v2)** login — a push wake, where
     * nothing was scanned. The approval UI shows these numbers and the user taps the
     * one matching the initiating surface; the tap is what proves the human is
     * looking at the right screen (see [VoidbindEngine.approveNumberMatch]). Empty
     * for a scanned v1 login, whose QR already carries its origin-binding.
     */
    val candidates: List<Int> = emptyList(),
) {
    /** True when this login must be approved by tapping a matched number, not a plain Approve. */
    val isNumberMatch: Boolean get() = candidates.isNotEmpty()
}

/**
 * A user-facing failure from an engine step that touches the network or the hardware
 * gate. [message] is already human-readable and says what to do ("Can't reach the relay
 * at <host>. Check Wi-Fi or your VPN and try again.") — never raw exception text.
 * [retryable] tells the UI whether a Retry that re-runs the SAME step (re-join the same
 * invite, re-mint the invite, re-confirm) can plausibly succeed; a protocol failure or
 * a cancelled biometric prompt is not retried against the same session.
 */
data class EngineFailure(
    val message: String,
    val kind: Kind,
    val retryable: Boolean = kind == Kind.UNREACHABLE || kind == Kind.REJECTED,
) {
    enum class Kind {
        /** No route to the relay / RP (Wi-Fi, VPN, DNS, TLS, timeout). Retry when the network is back. */
        UNREACHABLE,

        /** The peer never showed up: the invite expired unjoined. Retry = a fresh invite. */
        TIMEOUT,

        /** The relay was reached but refused (stale / used session, server error). */
        REJECTED,

        /** The bytes did not verify — do not retry the same session. */
        PROTOCOL,

        /** The human cancelled the biometric prompt. */
        CANCELLED,

        /**
         * A short-lived code went stale before it was used — a web-login id the RP no
         * longer knows (404/410 on the challenge fetch). Scan a fresh QR; not retryable.
         */
        EXPIRED,

        /**
         * A deliberate refusal the user can resolve: a step that is not allowed yet
         * (remove the phone's recovery copy before the paper is checked, renew a lapsed
         * device) or needs something this device does not have (a kept recovery copy, a
         * strong biometric). The message says what to do instead; not retryable as is.
         */
        NOT_YET,

        /** Anything else (a bug, a missing precondition such as no identity). */
        INTERNAL,
    }
}

/**
 * The result of an engine step that MUST NOT throw for a transport/hardware failure:
 * every suspending [VoidbindEngine] call returns one, so a blocking relay call that blows up inside
 * `withContext(Dispatchers.IO)` is turned into a value on the IO thread — it never
 * escapes the coroutine. (A call-site `runCatching` is not enough: when the calling
 * coroutine has already been cancelled, an exception thrown later by the blocking call
 * has no caller to deliver to and reaches the uncaught handler as a main-thread FATAL,
 * which is exactly the crash seen on-device.)
 */
sealed interface EngineResult<out T> {
    data class Ready<T>(val value: T) : EngineResult<T>
    data class Failed(val failure: EngineFailure) : EngineResult<Nothing>
}

/** The value of a [EngineResult.Ready], or null for a failure. */
fun <T> EngineResult<T>.valueOrNull(): T? = when (this) {
    is EngineResult.Ready -> value
    is EngineResult.Failed -> null
}

/** The failure of a [EngineResult.Failed], or null on success. */
fun EngineResult<*>.failureOrNull(): EngineFailure? = (this as? EngineResult.Failed)?.failure

/** SAS-compare state for the pair VERIFY step. */
data class PairSession(
    val thisDeviceName: String,
    val peerDeviceName: String,
    /** The 7-digit security code, grouped as `NNN NNNN`. */
    val securityCode: String,
    /**
     * The PEER's device signing key (`ed25519:<hex>`) as the relay reveal produced it,
     * when this side learned it — the initiator does (it is about to name that key in
     * the add op); the responder does not need it. Null otherwise.
     *
     * Not shown to anyone: it is what the same-phone one-tap path (ADR-0008) compares
     * the relying-party app's own local report against, so the SAS check can be settled
     * by the two apps instead of by the human.
     */
    val peerDeviceKey: String? = null,
)

/** The invite this device shows when it is the existing (initiator) side. */
data class PairInviteDisplay(
    val inviteId: String,
    val qrPayload: String,
    val expiresInSeconds: Int,
    /**
     * The relay session id this invite opened — the same value the invite tuple carries
     * as `session=`, so a relying-party app on this phone can name it back to us in its
     * `cruciform://pair-joined` callback (ADR-0008). Empty when unknown (preview data).
     */
    val session: String = "",
)
