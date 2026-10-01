package one.rarebit.cruciform.ui.flow

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import one.rarebit.cruciform.domain.EngineFailure
import one.rarebit.cruciform.domain.ScannedCode
import one.rarebit.cruciform.testing.ScriptedEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class LoginViewModelTest {

    @get:Rule
    val main = MainDispatcherRule()

    private val engine = ScriptedEngine()
    private val saved = SavedStateHandle()
    private val vm = LoginViewModel(engine, saved)
    private val code = engine.parseScanned(ScriptedEngine.LOGIN) as ScannedCode.WebLogin

    @Test
    fun `open fetches the request, shows it and persists the code`() = runTest {
        vm.open(code, fromScan = true)

        assertEquals(LoginViewModel.Event.Show(fromScan = true), vm.eventFlow.first())
        assertEquals(ScriptedEngine.REQUEST, vm.request.value)
        assertEquals(ScriptedEngine.LOGIN, saved.get<String>(LoginViewModel.KEY_CODE))
    }

    @Test
    fun `a failed fetch is a login error, clears the code and closes the scanner`() = runTest {
        engine.fetchResult = ScriptedEngine.failure(EngineFailure.Kind.EXPIRED, "Scan a fresh QR.")

        vm.open(code, fromScan = true)

        assertEquals(LoginViewModel.Event.FetchFailed(fromScan = true), vm.eventFlow.first())
        assertEquals(LoginErrorState("Scan a fresh QR.", expired = true), vm.loginError.value)
        assertNull(saved.get<String>(LoginViewModel.KEY_CODE))
        assertNull(vm.request.value)
    }

    @Test
    fun `approve signs and reports Approved`() = runTest {
        vm.open(code, fromScan = false)
        vm.eventFlow.first()

        vm.approve()

        assertEquals(LoginViewModel.Event.Approved, vm.eventFlow.first())
        assertTrue("approveLogin" in engine.calls)
        assertNull(vm.loginError.value)
    }

    @Test
    fun `a failed approval surfaces the engine's message`() = runTest {
        vm.open(code, fromScan = false)
        vm.eventFlow.first()
        engine.approveResult = ScriptedEngine.failure(EngineFailure.Kind.CANCELLED, "Authentication cancelled.")

        vm.approve(chosen = 27)

        assertEquals(LoginViewModel.Event.ApprovalFailed, vm.eventFlow.first())
        assertTrue("match:27" in engine.calls)
        assertEquals(LoginErrorState("Authentication cancelled."), vm.loginError.value)
    }

    @Test
    fun `approving with no code in flight fails without calling the engine`() = runTest {
        vm.approve()

        assertEquals(LoginViewModel.Event.ApprovalFailed, vm.eventFlow.first())
        assertEquals(LoginErrorState("Couldn't complete the sign-in."), vm.loginError.value)
        assertTrue(engine.calls.none { it.startsWith("approve") || it.startsWith("match") })
    }

    @Test
    fun `deny records the denial and reports Denied`() = runTest {
        vm.open(code, fromScan = false)
        vm.eventFlow.first()

        vm.deny()

        assertEquals(LoginViewModel.Event.Denied, vm.eventFlow.first())
        assertTrue("denyLogin" in engine.calls)
    }

    @Test
    fun `after process death the persisted code is re-fetched on resume`() = runTest {
        // A fresh ViewModel over the saved state the old one left behind.
        val restored = LoginViewModel(engine, SavedStateHandle(mapOf(LoginViewModel.KEY_CODE to ScriptedEngine.LOGIN)))
        assertEquals(ScriptedEngine.LOGIN, restored.pendingCode.value)
        assertNull(restored.request.value)

        restored.resume()

        assertEquals(LoginViewModel.Event.Show(fromScan = false), restored.eventFlow.first())
        assertEquals(ScriptedEngine.REQUEST, restored.request.value)
    }

    @Test
    fun `resume with nothing persisted does nothing`() = runTest {
        vm.resume()

        assertNull(withTimeoutOrNull(100) { vm.eventFlow.first() })
        assertTrue(engine.calls.isEmpty())
    }

    @Test
    fun `finish forgets the persisted code`() = runTest {
        vm.open(code, fromScan = false)
        vm.eventFlow.first()

        vm.finish()

        assertNull(vm.pendingCode.value)
    }

    @Test
    fun `a failed policy change is an engine error and the policy is re-read`() = runTest {
        engine.settingsResult = ScriptedEngine.failure(EngineFailure.Kind.INTERNAL, "Couldn't change it.")

        vm.setAlwaysAsk("rp.example.test", alwaysAsk = true)

        assertEquals("Couldn't change it.", vm.error.value?.failure?.message)
        assertEquals(ScriptedEngine.REQUEST.domain, vm.policy.value?.rp)
        vm.error.value!!.onDismiss()
        assertNull(vm.error.value)
    }

    @Test
    fun `an unknown code is a one-line login error`() {
        vm.showError("Not a Void-Which-Binds code.")
        assertEquals(LoginErrorState("Not a Void-Which-Binds code."), vm.loginError.value)
        vm.dismissLoginError()
        assertNull(vm.loginError.value)
    }
}
