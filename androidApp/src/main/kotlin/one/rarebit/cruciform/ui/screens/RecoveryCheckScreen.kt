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
import androidx.compose.runtime.toMutableStateList
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
 * Check a written recovery secret — or some groups of it — against this identity.
 * Nothing is signed: this proves the paper works before it is ever needed
 * (void-which-binds-go ADR-0010).
 *
 * [fields] are the labels of the inputs (one "Recovery secret" for a full drill; a few
 * "Group N" for the confirm step after creating). [onCheck] returns the success line
 * to show, or a failure whose message is shown inline. [onSkip], when given, offers
 * "Not now".
 *
 * With a single field, [onScan] offers to scan a printed recovery sheet instead of
 * typing; the result arrives as [scanned], fills the field (nothing is checked until
 * "Check") and is then [onScannedConsumed].
 */
@Composable
fun RecoveryCheckScreen(
    title: String,
    intro: String,
    fields: List<String>,
    onCheck: suspend (List<String>) -> EngineResult<String>,
    onDone: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onSkip: (() -> Unit)? = null,
    onScan: (() -> Unit)? = null,
    scanned: String? = null,
    onScannedConsumed: () -> Unit = {},
) {
    SecureScreen()
    val scope = rememberCoroutineScope()
    val values = remember(fields) { List(fields.size) { "" }.toMutableStateList() }
    var error by remember { mutableStateOf<String?>(null) }
    var success by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    ScannedSecretEffect(scanned.takeIf { fields.size == 1 }, onScannedConsumed) {
        values[0] = it
        error = null
    }

    Column(modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        AppTopBar(title = title, onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 24.dp)) {
            Text(intro, style = MaterialTheme.typography.bodyLarge, color = VbColors.TextSecondary)
            VSpace(20)
            fields.forEachIndexed { i, label ->
                OutlinedTextField(
                    value = values[i],
                    onValueChange = {
                        values[i] = it
                        error = null
                    },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(label) },
                    isError = error != null,
                    enabled = success == null,
                    textStyle = TextStyle(fontFamily = FontFamily.Monospace),
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None),
                    minLines = if (fields.size == 1) 3 else 1,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = VbColors.Mint,
                        unfocusedBorderColor = VbColors.Outline,
                        cursorColor = VbColors.Mint,
                        focusedLabelColor = VbColors.Mint,
                    ),
                )
                VSpace(10)
            }
            error?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium, color = VbColors.Coral)
                VSpace(10)
            }
            val done = success
            if (done != null) {
                Text(done, style = MaterialTheme.typography.bodyLarge, color = VbColors.Mint)
                VSpace(20)
                PrimaryButton(text = "Done", onClick = onDone, modifier = Modifier.fillMaxWidth())
            } else {
                ScanSheetButton(onScan.takeIf { fields.size == 1 }, enabled = !busy, spacing = 10)
                VSpace(10)
                PrimaryButton(
                    text = if (busy) "Checking…" else "Check",
                    onClick = {
                        if (busy) return@PrimaryButton
                        busy = true
                        scope.launch {
                            try {
                                when (val result = onCheck(values.toList())) {
                                    is EngineResult.Ready -> success = result.value
                                    is EngineResult.Failed -> error = result.failure.message
                                }
                            } finally {
                                busy = false
                            }
                        }
                    },
                    enabled = values.all { it.isNotBlank() } && !busy,
                    modifier = Modifier.fillMaxWidth(),
                )
                onSkip?.let {
                    VSpace(10)
                    OutlineButton(
                        text = "Not now",
                        onClick = it,
                        accent = VbColors.TextSecondary,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
    }
}
