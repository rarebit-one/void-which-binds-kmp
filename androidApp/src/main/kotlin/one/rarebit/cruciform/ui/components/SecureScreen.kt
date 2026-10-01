package one.rarebit.cruciform.ui.components

import android.app.Activity
import android.os.Build
import android.view.View
import android.view.Window
import android.view.WindowManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.platform.LocalView

/**
 * Marks the current screen as secure while it is composed. Two protections, because
 * each covers a different way off the screen:
 *
 *  - `FLAG_SECURE`: the OS blocks screenshots and screen recording and keeps the
 *    content out of the recents thumbnail.
 *  - **accessibility-data-sensitive** (Android 14+): only accessibility services that
 *    declare `isAccessibilityTool` (screen readers such as TalkBack) can read the
 *    content. `FLAG_SECURE` does not stop the accessibility tree, so without this any
 *    enabled accessibility service could read a revealed or typed recovery secret
 *    (void-which-binds-kmp#87). Below Android 14 there is no such control; nothing changes.
 *
 * Used on the recovery-secret, share, scan and pairing screens, which display material
 * that must never be captured.
 *
 * Both are window-level, and they are **reference-counted** here so they compose
 * correctly across a secure → secure navigation. Navigating directly between two
 * secure screens (e.g. Pair·Connect → Pair·Verify) interleaves the incoming screen's
 * set-up with the outgoing screen's `onDispose`; a naive per-screen set/clear lets the
 * outgoing clear run last and strip the protection off the incoming secure screen for
 * its whole lifetime. Counting acquisitions means it is on while *any* secure screen is
 * composed and cleared only when the last one leaves.
 */
@Composable
fun SecureScreen() {
    val view = LocalView.current
    DisposableEffect(Unit) {
        val window = (view.context as? Activity)?.window?.let(::ActivityWindow)
        SecureFlag.acquire(window)
        onDispose { SecureFlag.release(window) }
    }
}

/** What a secure screen changes on its window: the seam that keeps [SecureCounter] testable. */
internal interface SecureWindow {
    /** `FLAG_SECURE`: no screenshots, recordings or recents thumbnail. */
    fun setSecure(secure: Boolean)

    /** Only accessibility tools may read the content (Android 14+; a no-op below). */
    fun setAccessibilityDataSensitive(sensitive: Boolean)
}

/**
 * Reference counter for the window's protections. Confined to the main thread
 * (Compose effects run there), so a plain `Int` is safe. [acquire] always (re)asserts
 * both, idempotently; [release] clears them only when the count returns to zero.
 */
internal class SecureCounter {
    var count = 0
        private set

    fun acquire(window: SecureWindow?) {
        count += 1
        window?.setSecure(true)
        window?.setAccessibilityDataSensitive(true)
    }

    fun release(window: SecureWindow?) {
        count = (count - 1).coerceAtLeast(0)
        if (count == 0) {
            window?.setSecure(false)
            window?.setAccessibilityDataSensitive(false)
        }
    }
}

private val SecureFlag = SecureCounter()

/** The real window. Sensitivity goes on the decor view, so every descendant inherits it. */
private class ActivityWindow(private val window: Window) : SecureWindow {
    override fun setSecure(secure: Boolean) {
        val flag = WindowManager.LayoutParams.FLAG_SECURE
        if (secure) window.setFlags(flag, flag) else window.clearFlags(flag)
    }

    override fun setAccessibilityDataSensitive(sensitive: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // A plain setter call: the getter is isAccessibilityDataSensitive(): Boolean, so
            // Kotlin exposes no property for this int-valued setter.
            window.decorView.setAccessibilityDataSensitive(
                if (sensitive) View.ACCESSIBILITY_DATA_SENSITIVE_YES else View.ACCESSIBILITY_DATA_SENSITIVE_AUTO,
            )
        }
    }
}
