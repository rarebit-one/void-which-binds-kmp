package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
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
import one.rarebit.cruciform.domain.EngineResult
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScanSheetButton
import one.rarebit.cruciform.ui.components.ScannedSecretEffect
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * Restore an identity from a recovery secret. The library refuses a mistyped
 * secret at the bech32m checksum (the engine returns it as a Failed), which surfaces here
 * as an inline error — nothing is provisioned until it parses. [onUseShares] switches to
 * restoring from recovery shares instead.
 *
 * [onScan] opens the scanner for a printed recovery sheet; its result arrives as
 * [scanned], which fills the field (nothing restores until the button is pressed) and is
 * then [onScannedConsumed].
 */
@Composable
fun RestoreScreen(
    onBack: () -> Unit,
    onRestore: suspend (String) -> EngineResult<Unit>,
    onDone: () -> Unit,
    onUseShares: () -> Unit,
    modifier: Modifier = Modifier,
    onScan: (() -> Unit)? = null,
    scanned: String? = null,
    onScannedConsumed: () -> Unit = {},
) {
    SecureScreen()
    val scope = rememberCoroutineScope()
    var secret by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    ScannedSecretEffect(scanned, onScannedConsumed) {
        secret = it
        error = null
    }

    Column(modifier = modifier.fillMaxSize()) {
        AppTopBar(title = "Restore identity", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 24.dp)) {
            Text(
                "Enter your recovery secret",
                style = MaterialTheme.typography.headlineMedium,
                color = VbColors.TextPrimary,
            )
            VSpace(8)
            Text(
                "This rebuilds your identity on this device offline. No server is involved. A single wrong character is refused.",
                style = MaterialTheme.typography.bodyLarge,
                color = VbColors.TextSecondary,
            )
            VSpace(20)
            OutlinedTextField(
                value = secret,
                onValueChange = {
                    secret = it
                    error = null
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Recovery secret") },
                placeholder = { Text("void-which-binds1…") },
                isError = error != null,
                textStyle = TextStyle(fontFamily = FontFamily.Monospace),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
                minLines = 3,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = VbColors.Mint,
                    unfocusedBorderColor = VbColors.Outline,
                    cursorColor = VbColors.Mint,
                    focusedLabelColor = VbColors.Mint,
                ),
            )
            if (error != null) {
                VSpace(8)
                Text(error!!, style = MaterialTheme.typography.bodyMedium, color = VbColors.Coral)
            }
            VSpace(12)
            ScanSheetButton(onScan, enabled = !busy, spacing = 8)
            VSpace(12)
            PrimaryButton(
                text = if (busy) "Restoring…" else "Restore identity",
                onClick = {
                    if (busy) return@PrimaryButton
                    busy = true
                    error = null
                    scope.launch {
                        // The engine returns every failure as a value (a mistyped secret says
                        // what was wrong with it); only a cancellation unwinds past here.
                        try {
                            when (val result = onRestore(secret.trim())) {
                                is EngineResult.Ready -> onDone()
                                is EngineResult.Failed -> error = result.failure.message
                            }
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = secret.isNotBlank() && !busy,
                fill = VbColors.Mint,
                modifier = Modifier.fillMaxWidth(),
            )
            VSpace(10)
            OutlineButton(
                text = "I have recovery shares instead",
                onClick = onUseShares,
                enabled = !busy,
                accent = VbColors.TextSecondary,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
