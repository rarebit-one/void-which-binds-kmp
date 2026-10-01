package one.rarebit.cruciform.domain

import one.rarebit.cruciform.platform.BiometricAuthenticator
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.platform.StrongAuth
import one.rarebit.voidwhichbinds.RecoverySecret
import one.rarebit.voidwhichbinds.UserFingerprint
import one.rarebit.voidwhichbinds.UserIdentity

/**
 * The recovery secret as this device handles it: the copy the phone may keep, and
 * checks of the copy written down.
 *
 * The kept copy IS the genesis authority, which bypasses the co-signed remove quorum
 * (void-which-binds-go ADR-0008). So it is sealed only behind a strong biometric, every use
 * needs one (never the screen-lock PIN), and the user can remove it once the paper is
 * proven. Checking the paper signs nothing (void-which-binds-go ADR-0010).
 */
internal class RecoveryCopy(
    private val store: IdentityStore,
    private val biometric: BiometricAuthenticator,
    private val clock: () -> Long,
    private val dateLabel: (Long) -> String,
) {
    /**
     * Offer to keep [secret] on this phone, behind a strong biometric. With none
     * enrolled, or the prompt declined, the phone keeps no copy. True when kept.
     */
    suspend fun offerToKeep(secret: RecoverySecret): Boolean {
        val auth = biometric.authenticateStrong(KEEP_TITLE, STRONG_SUBTITLE)
        return auth == StrongAuth.SUCCESS && runCatching { store.keepRecoverySecret(secret.bytes) }.isSuccess
    }

    /**
     * Unseal the kept secret and derive the genesis identity, behind a **strong
     * biometric**. The identity is returned for one use and never cached.
     */
    suspend fun unsealGenesis(title: String): EngineResult<UserIdentity> {
        val auth = biometric.authenticateStrong(title, STRONG_SUBTITLE)
        return when (auth) {
            StrongAuth.CANCELLED -> cancelledFailure()

            StrongAuth.UNAVAILABLE -> strongBiometricRequiredFailure()

            StrongAuth.SUCCESS -> store.recoverySecret()
                ?.let { EngineResult.Ready(UserIdentity.fromSecret(RecoverySecret.of(it))) }
                ?: notYetFailure(COPY_GONE)
        }
    }

    /**
     * Split the kept secret into SLIP-39 recovery shares (void-which-binds-go ADR-0011: any 2
     * of 3, no passphrase), behind a **strong biometric**, as [unsealGenesis]. The
     * shares are returned for one showing and never stored; splitting revokes nothing,
     * so the written secret keeps working. A phone that keeps no copy is refused before
     * any prompt.
     */
    suspend fun split(): EngineResult<List<String>> {
        if (!store.hasUserKey()) return notYetFailure(NO_COPY)
        return when (biometric.authenticateStrong(SPLIT_TITLE, STRONG_SUBTITLE)) {
            StrongAuth.CANCELLED -> cancelledFailure()

            StrongAuth.UNAVAILABLE -> strongBiometricRequiredFailure()

            StrongAuth.SUCCESS -> store.recoverySecret()
                ?.let { raw ->
                    val shares = try {
                        RecoverySecret.of(raw).splitShares()
                    } finally {
                        raw.fill(0)
                    }
                    EngineResult.Ready(shares)
                }
                ?: notYetFailure(COPY_GONE)
        }
    }

    /**
     * Check a written [secret] against [persisted]'s identity without using it, and
     * record the check on a match. A typo throws from the parser (its reason becomes
     * the message); another identity's secret is a failure naming both fingerprints.
     */
    fun verify(secret: String, persisted: IdentityStore.Persisted): EngineResult<RecoveryCheck> {
        val candidate = UserIdentity.restore(secret)
        val matches = candidate.userPublicKey.contentEquals(persisted.userPublicKey)
        if (matches) store.markBackupChecked(clock())
        return if (matches) {
            EngineResult.Ready(RecoveryCheck(candidate.fingerprint))
        } else {
            internalFailure(
                "That secret belongs to a different identity (${candidate.fingerprint}). " +
                    "This identity is ${UserFingerprint.of(persisted.userPublicKey)}.",
            )
        }
    }

    /**
     * Remove the kept copy, behind a strong biometric: only once the paper has been
     * checked here and this device is a member ([lapsed] false), so it keeps renewing
     * itself without genesis.
     */
    suspend fun forget(lapsed: Boolean): EngineResult<Unit> {
        val refusal = when {
            !store.hasUserKey() -> NO_COPY

            store.backupCheckedAt() == null ->
                "Check your written recovery secret first (Settings → Test recovery secret): " +
                    "after this, it is the only copy."

            lapsed -> "This device must be a current member first, so it can renew itself without the recovery key."

            else -> null
        }
        return when {
            refusal != null -> notYetFailure(refusal)

            else -> when (biometric.authenticateStrong("Remove the recovery copy", STRONG_SUBTITLE)) {
                StrongAuth.CANCELLED -> cancelledFailure()

                StrongAuth.UNAVAILABLE -> strongBiometricRequiredFailure()

                StrongAuth.SUCCESS -> {
                    store.forgetRecoverySecret()
                    EngineResult.Ready(Unit)
                }
            }
        }
    }

    /** Whether the written secret has been checked here, and whether a drill is due. */
    fun status(): BackupStatus {
        val checkedAt = store.backupCheckedAt()
        return BackupStatus(
            confirmPending = store.backupPending(),
            lastCheckedLabel = checkedAt?.let { "Checked ${dateLabel(it)}" },
            drillDue = checkedAt != null && clock() - checkedAt > DRILL_INTERVAL_SECONDS,
        )
    }

    companion object {
        const val STRONG_SUBTITLE = "Confirm with your fingerprint or face"
        private const val KEEP_TITLE = "Keep a recovery copy on this phone"
        private const val SPLIT_TITLE = "Split into recovery shares"
        private const val NO_COPY = "This phone keeps no copy of the recovery secret."
        private const val COPY_GONE =
            "This phone's copy of the recovery secret is gone — enrolling a new fingerprint " +
                "or face erases it. Use your written recovery secret instead."

        /** Suggest checking the written secret again once a year. */
        private const val DRILL_INTERVAL_SECONDS = 365L * 24 * 60 * 60
    }
}
