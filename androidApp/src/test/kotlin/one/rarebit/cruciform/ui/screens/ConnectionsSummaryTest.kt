package one.rarebit.cruciform.ui.screens

import org.junit.Test
import kotlin.test.assertEquals

class ConnectionsSummaryTest {
    private val relay = "https://relay.example.test"
    private val notify = "https://notify.example.test"

    @Test
    fun `a server that is not set is said first, even when it is the build default`() {
        assertEquals("Not set · no pairing relay or push plane", connectionsSummary("", true, "", true))
        assertEquals("Pairing relay not set", connectionsSummary("", true, notify, false))
        assertEquals("Push plane not set", connectionsSummary(relay, false, "", true))
    }

    @Test
    fun `set servers are the build's own or custom`() {
        assertEquals("Using this build's servers", connectionsSummary(relay, true, notify, true))
        assertEquals("Custom servers set", connectionsSummary(relay, false, notify, true))
        assertEquals("Custom servers set", connectionsSummary(relay, true, notify, false))
    }
}
