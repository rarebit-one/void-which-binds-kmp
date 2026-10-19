package one.rarebit.cruciform.desktop.ui

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type

/** A link handed to the app (on the command line, or by a later launch), numbered so a repeat still lands. */
data class IncomingLink(val seq: Long, val value: String)

/**
 * The window's navigation state, above the screens, so the window's key handler and links
 * forwarded by a later launch ([one.rarebit.cruciform.desktop.SingleInstance]) can drive it.
 */
class AppState(initialLink: String? = null) {
    var screen by mutableStateOf(Screen.OVERVIEW)

    /** The latest link for Sign in or Approvals to fill in. */
    var incoming by mutableStateOf<IncomingLink?>(null)
        private set

    /** Bumped when the window should come to the front. */
    var raise by mutableStateOf(0L)
        private set

    private var seq = 0L

    init {
        initialLink?.let(::openLink)
    }

    /** Opens the screen a `void-which-binds:` link belongs to, with the link filled in. Signs nothing. */
    fun openLink(link: String) {
        when {
            link.startsWith(LOGIN_PREFIX) -> screen = Screen.SIGN_IN
            link.startsWith(APPROVE_PREFIX) -> screen = Screen.APPROVALS
            else -> return
        }
        incoming = IncomingLink(++seq, link)
    }

    /** A later launch arrived: show its link, if any, and come to the front. */
    fun forwarded(message: String) {
        if (message.isNotEmpty()) openLink(message)
        raise++
    }

    /** Ctrl+1 … Ctrl+6 open the screens in rail order, from anywhere in the window. */
    fun onKey(e: KeyEvent): Boolean {
        val target = shortcut(e.key, e.type, e.isCtrlPressed, e.isAltPressed || e.isShiftPressed || e.isMetaPressed)
            ?: return false
        screen = target
        return true
    }

    companion object {
        const val LOGIN_PREFIX = "void-which-binds:login"
        const val APPROVE_PREFIX = "void-which-binds:approve"
        private val DIGITS = listOf(Key.One, Key.Two, Key.Three, Key.Four, Key.Five, Key.Six)

        /** The screen Ctrl+digit opens: a key-down of 1…6 with Ctrl alone held; null otherwise. */
        fun shortcut(key: Key, type: KeyEventType, ctrl: Boolean, otherModifiers: Boolean): Screen? =
            if (type == KeyEventType.KeyDown && ctrl && !otherModifiers) {
                Screen.entries.getOrNull(DIGITS.indexOf(key)) // -1 (not a digit) gives null too
            } else {
                null
            }
    }
}
