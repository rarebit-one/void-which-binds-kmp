package one.rarebit.cruciform.desktop.ui

import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Navigation driven from outside the screens: links (argv or a later launch) and Ctrl+digit. */
class AppStateTest {
    @Test
    fun aLinkOpensItsScreenFilledInAndARepeatStillLands() {
        val s = AppState("void-which-binds:login?rp=x&id=1")
        assertEquals(Screen.SIGN_IN, s.screen)
        val first = s.incoming!!
        s.forwarded("void-which-binds:login?rp=x&id=1")
        assertEquals(first.value, s.incoming!!.value)
        assertTrue(s.incoming!!.seq > first.seq, "the same link again must still refill the screen")
        assertEquals(1L, s.raise)
        s.forwarded("void-which-binds:approve?h=abc")
        assertEquals(Screen.APPROVALS, s.screen)
    }

    @Test
    fun aRaiseRequestOrAForeignLinkChangesNothingButTheFront() {
        val s = AppState()
        s.forwarded("")
        s.openLink("https://site.example")
        assertEquals(Screen.OVERVIEW, s.screen)
        assertNull(s.incoming)
        assertEquals(1L, s.raise)
    }

    @Test
    fun ctrlDigitsOpenTheScreensInRailOrder() {
        val digits = listOf(Key.One, Key.Two, Key.Three, Key.Four, Key.Five, Key.Six)
        for ((i, k) in digits.withIndex()) {
            assertEquals(
                Screen.entries[i],
                AppState.shortcut(k, KeyEventType.KeyDown, ctrl = true, otherModifiers = false),
            )
        }
    }

    @Test
    fun otherKeysAreLeftToTheFocusedControl() {
        // Typing a digit into a field.
        assertNull(AppState.shortcut(Key.Two, KeyEventType.KeyDown, ctrl = false, otherModifiers = false))
        assertNull(AppState.shortcut(Key.Two, KeyEventType.KeyDown, ctrl = true, otherModifiers = true)) // Ctrl+Shift+2
        assertNull(AppState.shortcut(Key.Seven, KeyEventType.KeyDown, ctrl = true, otherModifiers = false))
        assertNull(AppState.shortcut(Key.Two, KeyEventType.KeyUp, ctrl = true, otherModifiers = false))
        assertNull(AppState.shortcut(Key.Tab, KeyEventType.KeyDown, ctrl = false, otherModifiers = false))
    }
}
