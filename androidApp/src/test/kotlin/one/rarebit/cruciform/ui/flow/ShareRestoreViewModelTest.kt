package one.rarebit.cruciform.ui.flow

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.domain.EngineFailure
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.testing.ScriptedEngine
import one.rarebit.voidwhichbinds.RecoverySecret
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class ShareRestoreViewModelTest {

    @get:Rule
    val main = MainDispatcherRule()

    private val engine = ScriptedEngine()
    private val vm = ShareRestoreViewModel(engine, combineDispatcher = Dispatchers.Unconfined)

    @Test
    fun `two Go-made shares restore the identity they were split from`() = runTest {
        assertTrue(vm.add(GO_SHARES[2]))
        assertEquals(ShareRestoreViewModel.State(given = 1, needed = 2), vm.state.value)
        assertTrue(vm.add(GO_SHARES[0]))
        assertTrue(vm.state.value.complete)

        assertTrue(vm.restore())

        assertEquals(listOf("restoreIdentity"), engine.calls)
        assertEquals(ScriptedEngine.BACKUP.rawSecret, engine.restoredSecret)
        assertEquals(ShareRestoreViewModel.State(), vm.state.value) // the shares are forgotten
    }

    @Test
    fun `a mistyped share is refused, named, and not kept`() {
        assertTrue(vm.add(GO_SHARES[0]))
        val words = GO_SHARES[1].split(" ").toMutableList()
        words[9] = if (words[9] == "acid") "acne" else "acid"

        assertFalse(vm.add(words.joinToString(" ")))

        val state = vm.state.value
        assertEquals(1, state.given)
        assertTrue(state.error!!.startsWith("Share 2 has a mistake"))
        assertTrue(vm.add(GO_SHARES[1])) // the corrected share goes in
        assertNull(vm.state.value.error)
    }

    @Test
    fun `the same share twice and a share of another set are refused`() {
        assertTrue(vm.add(GO_SHARES[0]))

        assertFalse(vm.add("  ${GO_SHARES[0]}\n"))
        assertTrue(vm.state.value.error!!.contains("already entered"))

        val otherSet = RecoverySecret.parse(ScriptedEngine.BACKUP.rawSecret).splitShares()
        assertFalse(vm.add(otherSet[1]))
        assertTrue(vm.state.value.error!!.contains("different set"))
        assertEquals(1, vm.state.value.given)
    }

    @Test
    fun `a failed restore keeps the shares so it can be retried`() = runTest {
        vm.add(GO_SHARES[0])
        vm.add(GO_SHARES[1])
        engine.restoreResult = ScriptedEngine.failure(EngineFailure.Kind.CANCELLED, "Authentication cancelled.")

        assertFalse(vm.restore())
        assertEquals("Authentication cancelled.", vm.state.value.error)
        assertTrue(vm.state.value.complete)

        engine.restoreResult = EngineResult.Ready(Unit)
        assertTrue(vm.restore())
    }

    @Test
    fun `start over forgets every share`() {
        vm.add(GO_SHARES[0])
        vm.startOver()

        assertEquals(ShareRestoreViewModel.State(), vm.state.value)
        assertTrue(vm.add(GO_SHARES[1]))
        assertEquals(1, vm.state.value.given)
    }

    private companion object {
        /**
         * `void-which-binds recovery split` (void-which-binds-go ADR-0011) of [ScriptedEngine.BACKUP]'s
         * secret, the library's pinned `counting-entropy` test secret: test data only.
         */
        val GO_SHARES = listOf(
            "regular agency academic acid avoid erode echo health fatigue thunder calcium iris change network " +
                "swimming funding painting inherit infant cricket bedroom hour income brother worthy agree sugar " +
                "apart charity snapshot universe behavior budget",
            "regular agency academic agency adapt desktop always grief patrol eclipse goat destroy estate froth " +
                "obtain elevator lunch evidence eraser carbon trend oasis envelope damage trip spray analysis " +
                "luxury trip scholar trend income teaspoon",
            "regular agency academic always admit decorate smug include acrobat trash texture vocal fishing " +
                "space fancy amazing tenant mayor amazing dance username acrobat ajar carbon gesture pharmacy " +
                "group airline picture dough revenue pupal advocate",
        )
    }
}
