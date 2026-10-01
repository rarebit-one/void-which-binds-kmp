package one.rarebit.cruciform.ui.flow

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import one.rarebit.cruciform.domain.EngineFailure
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.testing.ScriptedEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class OnboardingViewModelTest {

    @get:Rule
    val main = MainDispatcherRule()

    private val engine = ScriptedEngine()
    private val saved = SavedStateHandle()
    private val vm = OnboardingViewModel(engine, saved)

    @Test
    fun `create provisions once and holds the secret in memory only`() {
        vm.create()
        vm.create() // a recomposition / rotation re-runs the effect: no second identity

        assertEquals(listOf("createIdentity"), engine.calls)
        assertEquals(ScriptedEngine.BACKUP, vm.backup.value)
        assertEquals(true, saved.get<Boolean>(OnboardingViewModel.KEY_STARTED))
        assertTrue(saved.keys().none { saved.get<Any>(it).toString().contains(ScriptedEngine.BACKUP.rawSecret) })
    }

    @Test
    fun `after process death mid-create it does NOT provision a second identity`() = runTest {
        val restored = OnboardingViewModel(engine, SavedStateHandle(mapOf(OnboardingViewModel.KEY_STARTED to true)))

        restored.create()

        assertEquals(OnboardingViewModel.Event.Interrupted, restored.eventFlow.first())
        assertTrue(engine.calls.isEmpty())
        assertEquals(OnboardingViewModel.INTERRUPTED, restored.error.value?.failure?.message)
    }

    @Test
    fun `a failed create is a dialog, leaves the screen and can be tried again`() = runTest {
        engine.createResult = ScriptedEngine.failure(EngineFailure.Kind.CANCELLED, "Authentication cancelled.")

        vm.create()

        assertEquals(OnboardingViewModel.Event.CreateFailed, vm.eventFlow.first())
        assertEquals("Authentication cancelled.", vm.error.value?.failure?.message)
        assertNull(saved.get<Boolean>(OnboardingViewModel.KEY_STARTED))

        engine.createResult = EngineResult.Ready(ScriptedEngine.BACKUP)
        vm.create()
        assertEquals(ScriptedEngine.BACKUP, vm.backup.value)
    }

    @Test
    fun `finished forgets the secret and the flag`() {
        vm.create()
        vm.finished()

        assertNull(vm.backup.value)
        assertNull(saved.get<Boolean>(OnboardingViewModel.KEY_STARTED))
    }

    @Test
    fun `the confirm step asks for three groups past the fixed prefix`() {
        vm.create()

        val challenge = vm.challenge.value
        val groups = ScriptedEngine.BACKUP.groupedSecret.split(" ")
        assertEquals(OnboardingViewModel.CHALLENGE_SIZE, challenge.size)
        assertEquals(challenge.sorted(), challenge)
        assertTrue(challenge.all { it in OnboardingViewModel.FIRST_CHECKED_GROUP..groups.size })
        // Every group before the first checked one holds part of the fixed `void-which-binds1` prefix.
        val skipped = groups.take(OnboardingViewModel.FIRST_CHECKED_GROUP - 1).joinToString("")
        assertEquals(6, OnboardingViewModel.FIRST_CHECKED_GROUP)
        assertTrue(skipped.startsWith("void-which-binds1") && skipped.length - "void-which-binds1".length < 4)
    }

    @Test
    fun `the right groups confirm the backup, in any case`() = runTest {
        vm.create()
        val groups = ScriptedEngine.BACKUP.groupedSecret.split(" ")
        val answers = vm.challenge.value.map { " ${groups[it - 1].uppercase()} " }

        assertTrue(vm.confirmGroups(answers) is EngineResult.Ready)
        assertEquals(listOf("createIdentity", "confirmBackup"), engine.calls)
    }

    @Test
    fun `a wrong group names itself and records nothing`() = runTest {
        vm.create()
        val groups = ScriptedEngine.BACKUP.groupedSecret.split(" ")
        val challenge = vm.challenge.value
        val answers = challenge.mapIndexed { i, pos -> if (i == 1) "zzzz" else groups[pos - 1] }

        val result = vm.confirmGroups(answers)

        val failure = (result as EngineResult.Failed).failure
        assertTrue(failure.message.contains("group ${challenge[1]}"))
        assertEquals(listOf("createIdentity"), engine.calls)
    }

    @Test
    fun `restore passes the typed secret straight to the engine`() = runTest {
        assertEquals(EngineResult.Ready(Unit), vm.restore("void-which-binds1test"))
        assertEquals(listOf("restoreIdentity"), engine.calls)
    }
}
