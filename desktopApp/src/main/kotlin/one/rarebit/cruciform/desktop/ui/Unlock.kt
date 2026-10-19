package one.rarebit.cruciform.desktop.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import one.rarebit.cruciform.desktop.DesktopEngine
import one.rarebit.voidwhichbinds.custody.SealedFile

/**
 * Asks for the sealed device's passphrase and unlocks. The field never echoes it, and copy
 * and cut are off for a password field; the app never puts it on the clipboard. The text is
 * dropped from the field as soon as it is used. (A JVM string cannot be zeroed; the bytes
 * handed to the unlock are.)
 */
@Composable
fun UnlockDialog(engine: DesktopEngine, onUnlocked: () -> Unit, onDismiss: () -> Unit) {
    var text by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    fun submit() {
        if (busy || text.isEmpty()) return
        val bytes = text.encodeToByteArray()
        text = ""
        busy = true
        error = null
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching { engine.unlock(bytes) } }
            busy = false
            r.onSuccess { onUnlocked() }.onFailure {
                error = if (it is SealedFile.SealedFileException.OpenFailed) {
                    "That passphrase didn't open this device's keys."
                } else {
                    it.message ?: "Couldn't unlock."
                }
            }
        }
    }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text("Unlock this device") },
        text = {
            Column {
                Text("Enter the passphrase this device's keys are sealed with.")
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text("Passphrase") },
                    singleLine = true,
                    enabled = !busy,
                    visualTransformation = PasswordVisualTransformation(),
                    isError = error != null,
                    supportingText = {
                        Text(error ?: if (busy) "Unlocking… (this takes a moment)" else "")
                    },
                    keyboardActions = androidx.compose.foundation.text.KeyboardActions(onDone = { submit() }),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        imeAction = androidx.compose.ui.text.input.ImeAction.Done,
                    ),
                )
            }
        },
        confirmButton = { TextButton(onClick = ::submit, enabled = !busy && text.isNotEmpty()) { Text("Unlock") } },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Cancel") } },
    )
}
