package one.rarebit.cruciform.platform

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * The set of unlock factors a prompt accepts. Named in one place so the security
 * boundary is a constant a test can pin, not a flag typed at each call site.
 */
object PresencePolicy {
    /**
     * A low-stakes user-presence check: **strong (class-3) biometric OR the device
     * credential** (PIN / pattern / password). Used for acts that touch only THIS
     * device or are not fleet-destructive — approving a login, revealing the recovery
     * secret, confirming this device's own enrolment, re-consenting to use the key
     * after the keystore window lapses. The credential fallback keeps a phone with a
     * failed/absent fingerprint sensor usable.
     */
    val ANY: Int =
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL

    /**
     * A **strong-biometric-only** check — *no* device-credential fallback. Used for
     * destructive / authority acts on the identity's device set: removing another
     * device, and authorising a new one. This closes the "unlocked stolen phone whose
     * PIN is known" hole — possession of the screen-lock secret must NOT be enough to
     * purge the fleet or admit an attacker's device. Someone who cannot satisfy a
     * strong biometric recovers with the recovery secret (genesis), which is the
     * designed fallback, rather than through the screen lock.
     */
    val DESTRUCTIVE: Int = BiometricManager.Authenticators.BIOMETRIC_STRONG
}

/** How a [PresencePolicy.DESTRUCTIVE] check resolved. */
enum class StrongAuth {
    /** A strong biometric matched. */
    SUCCESS,

    /** The user dismissed the prompt (or it errored). Retryable. */
    CANCELLED,

    /**
     * No strong biometric is enrolled / available on this device, so the check could
     * not even be offered. Deliberately NOT a silent fall-through to the device
     * credential — the caller must route the user to recovery instead.
     */
    UNAVAILABLE,
}

/**
 * Presents a user-presence check. The device signing key's hardware wrapping key is
 * bound to a short post-authentication window ([one.rarebit.voidwhichbinds.DeviceKeyStore]);
 * when the engine hits [one.rarebit.voidwhichbinds.AuthenticationRequiredException], it
 * calls [authenticate], and on success retries the signature within the window.
 */
interface BiometricAuthenticator {
    /**
     * Show a [PresencePolicy.ANY] prompt and suspend until the user resolves it.
     * True on success.
     */
    suspend fun authenticate(title: String, subtitle: String): Boolean

    /**
     * Show a [PresencePolicy.DESTRUCTIVE] prompt — strong biometric only, no
     * device-credential fallback — for a fleet-destructive / authority act. Returns
     * [StrongAuth.UNAVAILABLE] without prompting when this device has no strong
     * biometric, so the caller can point the user at recovery rather than loop.
     */
    suspend fun authenticateStrong(title: String, subtitle: String): StrongAuth
}

/** Backed by androidx `BiometricPrompt`; must be constructed with a [FragmentActivity]. */
class AndroidBiometricAuthenticator(private val activity: FragmentActivity) : BiometricAuthenticator {

    override suspend fun authenticate(title: String, subtitle: String): Boolean = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { cont ->
            val prompt = prompt { ok -> if (cont.isActive) cont.resume(ok) }
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setAllowedAuthenticators(PresencePolicy.ANY)
                .build()
            prompt.authenticate(info)
        }
    }

    override suspend fun authenticateStrong(title: String, subtitle: String): StrongAuth =
        withContext(Dispatchers.Main) {
            // Do not even offer the prompt if a strong biometric cannot be used: with
            // DEVICE_CREDENTIAL excluded there is no fallback, so an unavailable sensor
            // would just error. Surface that distinctly so the UI sends the user to
            // recovery instead of retrying into the same wall.
            val canStrong = BiometricManager.from(activity)
                .canAuthenticate(PresencePolicy.DESTRUCTIVE) == BiometricManager.BIOMETRIC_SUCCESS
            if (!canStrong) return@withContext StrongAuth.UNAVAILABLE

            suspendCancellableCoroutine { cont ->
                val prompt = prompt { ok ->
                    if (cont.isActive) cont.resume(if (ok) StrongAuth.SUCCESS else StrongAuth.CANCELLED)
                }
                val info = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setAllowedAuthenticators(PresencePolicy.DESTRUCTIVE)
                    // A negative button is REQUIRED when DEVICE_CREDENTIAL is not among
                    // the allowed authenticators; without it PromptInfo.build() throws.
                    .setNegativeButtonText("Cancel")
                    .setConfirmationRequired(true)
                    .build()
                prompt.authenticate(info)
            }
        }

    private inline fun prompt(crossinline onDone: (Boolean) -> Unit): BiometricPrompt = BiometricPrompt(
        activity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onDone(true)
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onDone(false)
            override fun onAuthenticationFailed() {
                // A single non-match — keep the prompt open for a retry.
            }
        },
    )
}
