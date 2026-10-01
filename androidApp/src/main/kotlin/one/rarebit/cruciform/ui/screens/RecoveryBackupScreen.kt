package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Print
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.domain.RecoveryBackup
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.WashCard
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType

/**
 * Recovery backup (Mockup 7): show, warn, gate behind two acknowledgements. [onPrint]
 * opens the system print dialog for the recovery sheet (QR code + groups, void-which-binds-go
 * `recovery/sheet`), an alternative to copying the groups by hand.
 */
@Composable
fun RecoveryBackupScreen(
    backup: RecoveryBackup,
    onBack: () -> Unit,
    onSaved: () -> Unit,
    onPrint: () -> Unit,
    stepLabel: String = "1 of 3 · BACKUP REQUIRED",
    modifier: Modifier = Modifier,
) {
    SecureScreen()
    var revealed by remember { mutableStateOf(true) }
    var wroteDown by remember { mutableStateOf(false) }
    var canRead by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        AppTopBar(title = "Recovery backup", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 24.dp)) {
            Text(stepLabel, style = VbType.SectionLabel, color = VbColors.Amber)
            VSpace(20)

            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Rounded.VpnKey,
                    contentDescription = null,
                    tint = VbColors.Amber,
                    modifier = Modifier.size(60.dp),
                )
                VSpace(12)
                Text(
                    "Save your recovery secret",
                    style = MaterialTheme.typography.headlineSmall,
                    color = VbColors.TextPrimary,
                    textAlign = TextAlign.Center,
                )
            }

            VSpace(20)
            WashCard(accent = VbColors.Amber, wash = VbColors.AmberWash, modifier = Modifier.fillMaxWidth()) {
                Row {
                    Icon(
                        Icons.Rounded.WarningAmber,
                        contentDescription = null,
                        tint = VbColors.Amber,
                        modifier = Modifier.size(28.dp),
                    )
                    HSpace(12)
                    Column {
                        Text(
                            "Write this down — it is the only way to recover your identity.",
                            style = MaterialTheme.typography.titleMedium,
                            color = VbColors.Amber,
                            fontWeight = FontWeight.SemiBold,
                        )
                        VSpace(6)
                        Text(
                            "Cruciform cannot reset it. Anyone with this secret can take over your identity.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = VbColors.TextSecondary,
                        )
                    }
                }
            }

            VSpace(18)
            VbCard(
                modifier = Modifier.fillMaxWidth(),
                border = androidx.compose.foundation.BorderStroke(1.dp, VbColors.Mint.copy(alpha = 0.5f)),
            ) {
                Column(Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("RECOVERY SECRET", style = VbType.SectionLabel, color = VbColors.Mint)
                        Spacer(Modifier.weight(1f))
                        IconButton(onClick = { revealed = !revealed }) {
                            Icon(
                                if (revealed) Icons.Rounded.Visibility else Icons.Rounded.VisibilityOff,
                                contentDescription = if (revealed) "Hide" else "Show",
                                tint = VbColors.Mint,
                            )
                        }
                    }
                    VSpace(6)
                    Text(
                        if (revealed) backup.groupedSecret else "•••• •••• •••• •••• •••• ••••",
                        style = VbType.RecoveryMono,
                        color = VbColors.Mint,
                    )
                    // No copy action: the root secret must not pass through the clipboard,
                    // which keyboards and clipboard managers sync off the device. Write it down.
                    VSpace(14)
                    Text(
                        if (backup.keptOnDevice) {
                            "This phone also keeps a copy, behind your fingerprint or face."
                        } else {
                            "This phone keeps no copy. What you write down is the only one."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = VbColors.TextSecondary,
                    )
                }
            }

            VSpace(12)
            OutlineButton(
                text = "Print recovery sheet",
                onClick = onPrint,
                accent = VbColors.Mint,
                leadingIcon = Icons.Rounded.Print,
                modifier = Modifier.fillMaxWidth(),
            )
            VSpace(8)
            Text(
                "Prints the secret as a QR code and in groups. Print at 100% to a printer you trust; " +
                    "don't choose \"Save as PDF\".",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
            )

            VSpace(12)
            Text(
                "Store offline. Do not save in screenshots, email, or cloud notes.",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
            )

            VSpace(16)
            AckRow("I wrote down or printed the complete secret", wroteDown) { wroteDown = it }
            AckRow("I can read every group clearly", canRead) { canRead = it }

            VSpace(20)
            PrimaryButton(
                text = "I've saved it",
                onClick = onSaved,
                enabled = wroteDown && canRead,
                fill = VbColors.Mint,
                modifier = Modifier.fillMaxWidth(),
            )
            VSpace(14)
            Text(
                "Remind me what this protects",
                style = MaterialTheme.typography.labelLarge,
                color = VbColors.Mint,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
            VSpace(16)
            Text(
                "Screenshots disabled on this screen",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun AckRow(text: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onChange(!checked) }
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(
            checked = checked,
            onCheckedChange = onChange,
            colors = CheckboxDefaults.colors(
                checkedColor = VbColors.Mint,
                uncheckedColor = VbColors.Outline,
                checkmarkColor = VbColors.OnMint,
            ),
        )
        HSpace(6)
        Text(text, style = MaterialTheme.typography.bodyLarge, color = VbColors.TextPrimary)
    }
}
