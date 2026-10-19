package one.rarebit.cruciform.desktop

import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import one.rarebit.cruciform.desktop.ui.App
import one.rarebit.cruciform.desktop.ui.AppState
import one.rarebit.voidwhichbinds.custody.GoDeviceDir
import one.rarebit.voidwhichbinds.net.JdkHttpTransport
import java.awt.EventQueue

/**
 * Cruciform for the desktop: this machine's sealed device (void-which-binds-go's device
 * directory, or `VOID_WHICH_BINDS_DEVICE_DIR`). An argument that is a `void-which-binds:login`
 * or `void-which-binds:approve` link opens on that screen with it filled in, in the window
 * that is already open if there is one.
 */
fun main(args: Array<String>) {
    val link = args.firstOrNull { it.startsWith("void-which-binds:") }
    // One instance per user: a later launch (a browser opening a link) hands its link to the
    // running window and exits, rather than opening a second window over the same device.
    val instance = when (val claim = SingleInstance(SingleInstance.defaultDir()).claim(link.orEmpty())) {
        is SingleInstance.Primary -> claim

        SingleInstance.Forwarded -> return

        SingleInstance.Unreachable -> null

        // the running one is wedged: run alone, not vanish
        SingleInstance.Untrusted -> null // no private runtime dir: no handoff, run alone
    }
    val state = AppState(link)
    instance?.serve { message -> EventQueue.invokeLater { state.forwarded(message) } }
    val engine =
        DesktopEngine(GoDeviceDir(GoDeviceDir.defaultDir()), DesktopSettings.Store.default(), JdkHttpTransport())
    application {
        Window(
            onCloseRequest = {
                engine.close()
                instance?.close()
                exitApplication()
            },
            title = "Cruciform",
            state = rememberWindowState(width = 960.dp, height = 720.dp),
            onPreviewKeyEvent = state::onKey,
        ) {
            LaunchedEffect(state.raise) {
                if (state.raise > 0) {
                    window.isMinimized = false
                    // toFront only. A window.requestFocus() here moves AWT focus from the
                    // Compose layer to the frame itself, and no key reaches Compose after it:
                    // Tab and the Ctrl+digit shortcuts go dead. Activation restores the focus.
                    window.toFront()
                }
            }
            App(engine, state)
        }
    }
}
