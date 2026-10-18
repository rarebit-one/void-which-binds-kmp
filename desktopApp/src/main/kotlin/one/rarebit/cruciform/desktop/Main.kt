package one.rarebit.cruciform.desktop

import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import one.rarebit.cruciform.desktop.ui.App
import one.rarebit.voidwhichbinds.custody.GoDeviceDir
import one.rarebit.voidwhichbinds.net.JdkHttpTransport

/**
 * Cruciform for the desktop: this machine's sealed device (void-which-binds-go's device
 * directory, or `VOID_WHICH_BINDS_DEVICE_DIR`). An argument that is a `void-which-binds:login`
 * or `void-which-binds:approve` link opens on that screen with it filled in.
 */
fun main(args: Array<String>) {
    val engine =
        DesktopEngine(GoDeviceDir(GoDeviceDir.defaultDir()), DesktopSettings.Store.default(), JdkHttpTransport())
    val link = args.firstOrNull { it.startsWith("void-which-binds:") }
    application {
        Window(
            onCloseRequest = {
                engine.close()
                exitApplication()
            },
            title = "Cruciform",
            state = rememberWindowState(width = 960.dp, height = 720.dp),
        ) {
            App(engine, link)
        }
    }
}
