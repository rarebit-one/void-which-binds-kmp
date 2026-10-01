package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.domain.OffloadCoordinator
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.DangerButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType

@Composable
fun OffloadApprovalScreen(
    state: OffloadCoordinator.State,
    onConfirmPair: () -> Unit,
    onApproveUnwrap: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    SecureScreen()
    Column(modifier.fillMaxSize().background(VbColors.Background).verticalScroll(rememberScrollState())) {
        AppTopBar(title = "Cruciform offload", onBack = onClose)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 28.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            when (state) {
                OffloadCoordinator.State.Idle -> {
                    Text("No offload request is active.", style = MaterialTheme.typography.bodyLarge, color = VbColors.TextSecondary)
                }

                OffloadCoordinator.State.Connecting -> {
                    VSpace(64)
                    CircularProgressIndicator(color = VbColors.Mint)
                    VSpace(18)
                    Text("Connecting to Heyarr Desktop…", style = MaterialTheme.typography.bodyLarge, color = VbColors.TextPrimary)
                    Text("Keep Cruciform open while the relay exchange completes.", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary, textAlign = TextAlign.Center)
                }

                is OffloadCoordinator.State.CompareCode -> {
                    Text("PAIR THIS DESKTOP", style = VbType.SectionLabel, color = VbColors.Mint)
                    VSpace(18)
                    Text("Compare security codes", style = MaterialTheme.typography.headlineMedium, color = VbColors.TextPrimary)
                    VSpace(8)
                    Text("Confirm only if the same code is shown by Heyarr Desktop.", style = MaterialTheme.typography.bodyLarge, color = VbColors.TextSecondary, textAlign = TextAlign.Center)
                    VSpace(24)
                    VbCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.fillMaxWidth().padding(vertical = 28.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(state.code, style = VbType.SecurityCode, color = VbColors.Mint)
                            VSpace(10)
                            Text("A mismatch can mean someone intercepted pairing.", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary, textAlign = TextAlign.Center)
                        }
                    }
                    VSpace(22)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        DangerButton("Cancel", onClick = onClose, leadingIcon = Icons.Rounded.Close, modifier = Modifier.weight(1f))
                        PrimaryButton("Codes match", onClick = onConfirmPair, leadingIcon = Icons.Rounded.Check, fill = VbColors.Mint, modifier = Modifier.weight(1f))
                    }
                    VSpace(12)
                    Text("Pairing is pinned after strong-biometric confirmation.", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextMuted, textAlign = TextAlign.Center)
                }

                is OffloadCoordinator.State.UnwrapApproval -> {
                    Text("UNLOCK AN ENCRYPTED SPACE", style = VbType.SectionLabel, color = VbColors.Mint)
                    VSpace(18)
                    Text("Approve this desktop?", style = MaterialTheme.typography.headlineMedium, color = VbColors.TextPrimary)
                    VSpace(8)
                    Text("${state.desktop} is asking Cruciform to unwrap a space key. The request is verified against the desktop pinned during pairing.", style = MaterialTheme.typography.bodyLarge, color = VbColors.TextSecondary, textAlign = TextAlign.Center)
                    VSpace(24)
                    VbCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Rounded.Lock, contentDescription = null, tint = VbColors.Mint)
                            VSpace(10)
                            Text("The space key is returned only to this request's temporary encryption key.", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary, textAlign = TextAlign.Center)
                        }
                    }
                    VSpace(22)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        DangerButton("Deny", onClick = onClose, leadingIcon = Icons.Rounded.Close, modifier = Modifier.weight(1f))
                        PrimaryButton("Approve", onClick = onApproveUnwrap, leadingIcon = Icons.Rounded.Fingerprint, fill = VbColors.Mint, modifier = Modifier.weight(1f))
                    }
                    VSpace(12)
                    Text("Strong-biometric confirmation is required. The space key stays in memory only for this reply.", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextMuted, textAlign = TextAlign.Center)
                }

                is OffloadCoordinator.State.Working -> {
                    VSpace(48)
                    CircularProgressIndicator(color = VbColors.Mint)
                    VSpace(18)
                    Text(state.message, style = MaterialTheme.typography.bodyLarge, color = VbColors.TextPrimary)
                }

                is OffloadCoordinator.State.Complete -> {
                    Text("COMPLETE", style = VbType.SectionLabel, color = VbColors.Mint)
                    VSpace(18)
                    Text(state.message, style = MaterialTheme.typography.headlineSmall, color = VbColors.TextPrimary, textAlign = TextAlign.Center)
                    VSpace(24)
                    PrimaryButton("Done", onClick = onClose, fill = VbColors.Mint, modifier = Modifier.fillMaxWidth())
                }

                is OffloadCoordinator.State.Failed -> {
                    Text("Couldn’t complete the offload", style = MaterialTheme.typography.headlineSmall, color = VbColors.TextPrimary)
                    VSpace(12)
                    Text(state.message, style = MaterialTheme.typography.bodyLarge, color = VbColors.TextSecondary, textAlign = TextAlign.Center)
                    VSpace(24)
                    DangerButton("Close", onClick = onClose, leadingIcon = Icons.Rounded.Close, modifier = Modifier.fillMaxWidth())
                }
            }
        }
    }
}
