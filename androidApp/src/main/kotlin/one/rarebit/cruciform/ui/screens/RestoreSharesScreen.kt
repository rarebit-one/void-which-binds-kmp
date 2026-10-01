package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.flow.ShareRestoreViewModel
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * Restore an identity from SLIP-39 recovery shares (void-which-binds-go ADR-0011), typed one at
 * a time. Each share is checked as it is added and a refused one is named with its
 * reason; the count runs toward the threshold the first share states; with exactly
 * enough in, "Restore identity" combines them offline and restores.
 *
 * The draft is composition state only (like [RestoreScreen]'s secret), never saved;
 * the accepted shares live in memory in [ShareRestoreViewModel]. Typing only: scanning
 * a share's QR code is not offered here.
 */
@Composable
fun RestoreSharesScreen(
    state: ShareRestoreViewModel.State,
    onAdd: (String) -> Boolean,
    onRestore: suspend () -> Boolean,
    onStartOver: () -> Unit,
    onBack: () -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
) {
    SecureScreen()
    val scope = rememberCoroutineScope()
    var draft by remember { mutableStateOf("") }

    Column(modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        AppTopBar(title = "Restore from shares", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 24.dp)) {
            Text(
                "Enter your recovery shares",
                style = MaterialTheme.typography.headlineMedium,
                color = VbColors.TextPrimary,
            )
            VSpace(8)
            Text(
                "Type each share whole, one at a time, in any order. Each is checked as you add it, " +
                    "and a single wrong word is caught. This rebuilds your identity on this device offline.",
                style = MaterialTheme.typography.bodyLarge,
                color = VbColors.TextSecondary,
            )
            VSpace(20)
            Text(
                progressLabel(state),
                style = MaterialTheme.typography.titleMedium,
                color = if (state.complete) VbColors.Mint else VbColors.TextPrimary,
            )
            VSpace(12)
            if (!state.complete) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = { draft = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Share ${state.given + 1}") },
                    placeholder = { Text("The share's words, separated by spaces") },
                    isError = state.error != null,
                    textStyle = TextStyle(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
                    minLines = 4,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = VbColors.Mint,
                        unfocusedBorderColor = VbColors.Outline,
                        cursorColor = VbColors.Mint,
                        focusedLabelColor = VbColors.Mint,
                    ),
                )
            }
            state.error?.let {
                VSpace(8)
                Text(it, style = MaterialTheme.typography.bodyMedium, color = VbColors.Coral)
            }
            VSpace(20)
            if (state.complete) {
                PrimaryButton(
                    text = if (state.busy) "Restoring…" else "Restore identity",
                    onClick = {
                        if (state.busy) return@PrimaryButton
                        // restore() returns every failure as State.error; only a
                        // cancellation unwinds past here.
                        scope.launch { if (onRestore()) onDone() }
                    },
                    enabled = !state.busy,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                PrimaryButton(
                    text = "Add share",
                    onClick = { if (onAdd(draft)) draft = "" },
                    enabled = draft.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (state.given > 0) {
                VSpace(10)
                OutlineButton(
                    text = "Start over",
                    onClick = {
                        draft = ""
                        onStartOver()
                    },
                    enabled = !state.busy,
                    accent = VbColors.TextSecondary,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

private fun progressLabel(state: ShareRestoreViewModel.State): String {
    val needed = state.needed
    return when {
        needed == null -> "No shares entered yet"
        state.complete -> "$needed of $needed shares entered: ready to restore"
        else -> "${state.given} of $needed needed"
    }
}
