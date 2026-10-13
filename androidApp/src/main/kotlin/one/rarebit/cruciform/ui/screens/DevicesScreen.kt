package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.domain.MemberDevice
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.IconCircle
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.StatusPill
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.VbHairline
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType

/**
 * Manage → **Devices**: the identity's device set as THIS device evaluates it from
 * the membership ops it holds (ADR-0005). Every row is a member; any member can add
 * the next ("Add a device") and remove another — a remove is signed by this device's
 * hardware key behind a biometric prompt and pushed to the relying parties. This
 * device is listed but cannot remove itself here.
 */
@Composable
fun DevicesScreen(
    devices: List<MemberDevice>,
    onBack: () -> Unit,
    onAddDevice: () -> Unit,
    onRemove: (MemberDevice) -> Unit,
    modifier: Modifier = Modifier,
) {
    var pendingRemove by remember { mutableStateOf<MemberDevice?>(null) }

    pendingRemove?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingRemove = null },
            confirmButton = {
                TextButton(onClick = {
                    pendingRemove = null
                    onRemove(target)
                }) { Text("Remove", color = VbColors.Coral) }
            },
            dismissButton = { TextButton(onClick = { pendingRemove = null }) { Text("Cancel") } },
            title = { Text("Remove ${target.fingerprint}?") },
            text = {
                Text(
                    "That device stops being a member of your identity. Every site you sign in to " +
                        "learns the removal from the next login or push. Only your recovery secret can re-admit it.",
                )
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        AppTopBar(title = "Devices", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 28.dp)) {
            Text(
                "Every device here is a member of your identity. Any of them can add the next one, and any can remove another.",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextSecondary,
            )
            VSpace(16)
            if (devices.isEmpty()) {
                EmptyDevices()
            } else {
                VbCard(modifier = Modifier.fillMaxWidth()) {
                    Column {
                        devices.forEachIndexed { i, d ->
                            DeviceRow(d, onRemove = { pendingRemove = d })
                            if (i < devices.lastIndex) VbHairline(Modifier.padding(horizontal = 16.dp))
                        }
                    }
                }
            }
            VSpace(20)
            PrimaryButton(text = "Add a device", onClick = onAddDevice, modifier = Modifier.fillMaxWidth())
            VSpace(12)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Rounded.Lock,
                    contentDescription = null,
                    tint = VbColors.TextMuted,
                    modifier = Modifier.size(16.dp),
                )
                HSpace(8)
                Text(
                    "Adding and removing are signed by this device's hardware key. No recovery secret is used.",
                    style = MaterialTheme.typography.bodySmall,
                    color = VbColors.TextMuted,
                )
            }
        }
    }
}

@Composable
private fun DeviceRow(d: MemberDevice, onRemove: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
        IconCircle(
            Icons.Rounded.Smartphone,
            tint = if (d.isThisDevice) VbColors.Mint else VbColors.Fern,
            background = (if (d.isThisDevice) VbColors.Mint else VbColors.Fern).copy(alpha = 0.12f),
        )
        HSpace(14)
        Column(Modifier.weight(1f)) {
            Text("dev · ${d.fingerprint}", style = VbType.Mono, color = VbColors.TextPrimary)
            Text(
                "admitted ${d.admittedLabel} by ${d.admittedByLabel}",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextSecondary,
            )
            Text(d.expiresLabel, style = MaterialTheme.typography.bodySmall, color = VbColors.TextMuted)
            if (d.isThisDevice) {
                VSpace(6)
                StatusPill("This device", accent = VbColors.Mint, leadingIcon = Icons.Rounded.Devices)
            }
        }
        if (!d.isThisDevice) {
            HSpace(8)
            OutlineButton("Remove", onClick = onRemove, accent = VbColors.Coral)
        }
    }
}

@Composable
private fun EmptyDevices() {
    VbCard(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                Icons.Rounded.Devices,
                contentDescription = null,
                tint = VbColors.TextMuted,
                modifier = Modifier.size(36.dp),
            )
            VSpace(10)
            Text(
                "No members found — this device's ops don't evaluate to a membership. Restore from the recovery secret.",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextSecondary,
                textAlign = TextAlign.Center,
            )
        }
    }
}
