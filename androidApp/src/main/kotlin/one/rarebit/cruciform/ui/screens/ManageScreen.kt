// Compose components are PascalCase by convention; layout spacing is literal dp.
// A screen reads top to bottom as one composable, built from small private sections.
@file:Suppress(
    "FunctionNaming",
    "MagicNumber",
    "ktlint:standard:function-naming",
    "LongMethod",
    "TooManyFunctions",
)

package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.AddCircle
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Groups
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.BuildConfig
import one.rarebit.cruciform.domain.HardwareBacking
import one.rarebit.cruciform.domain.IdentityState
import one.rarebit.cruciform.domain.TrustedSite
import one.rarebit.cruciform.ui.components.CruciformMark
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.IconCircle
import one.rarebit.cruciform.ui.components.IdentityFingerprint
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.RowItem
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SectionLabel
import one.rarebit.cruciform.ui.components.SiteAvatar
import one.rarebit.cruciform.ui.components.StatusPill
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.VbHairline
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy

/**
 * Manage: everything about the identity that Home keeps out of the way — the identity
 * fingerprint (to compare and copy), this phone's key protection, biometric gate and
 * membership, the device set, trusted sites and their policies, the recovery secret,
 * and (one level further down, in [ConnectionsScreen]) the servers this phone dials.
 *
 * Every action is the one Settings offered; only where it lives changed. [connections]
 * labels the Connections row (see [connectionsSummary]).
 */
@Composable
@Suppress("LongParameterList") // A screen's callbacks are hoisted to the nav graph, one per action.
fun ManageScreen(
    state: IdentityState.Active,
    connections: String,
    onCopyIdentity: () -> Unit,
    onRename: () -> Unit,
    onToggleBiometric: (Boolean) -> Unit,
    onRenew: () -> Unit,
    onAddDevice: () -> Unit,
    onDevices: () -> Unit,
    onRevoke: (TrustedSite) -> Unit,
    onApprovalActivity: () -> Unit,
    onRecoveryBackup: () -> Unit,
    onTestRecovery: () -> Unit,
    onForgetRecovery: () -> Unit,
    onSplitShares: () -> Unit,
    onConnections: () -> Unit,
    onAbout: () -> Unit,
    onSecurity: () -> Unit,
    onLicenses: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmForget by remember { mutableStateOf(false) }
    if (confirmForget) {
        AlertDialog(
            onDismissRequest = { confirmForget = false },
            confirmButton = {
                TextButton(onClick = {
                    confirmForget = false
                    onForgetRecovery()
                }) { Text("Remove", color = VbColors.Coral) }
            },
            dismissButton = { TextButton(onClick = { confirmForget = false }) { Text("Cancel") } },
            title = { Text("Remove the copy on this phone?") },
            text = {
                Text(
                    "Your written recovery secret becomes the only copy. This phone keeps signing in and " +
                        "renewing itself, but re-admitting a device will need the paper.",
                )
            },
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(ScreenPadding)
            .padding(top = 20.dp, bottom = 28.dp),
    ) {
        Text("Manage", style = MaterialTheme.typography.headlineLarge, color = VbColors.TextPrimary)
        Text(
            "Your identity, devices, sites and recovery.",
            style = MaterialTheme.typography.bodyMedium,
            color = VbColors.TextMuted,
        )

        VSpace(20)
        IdentityCard(state, onCopyIdentity)

        VSpace(24)
        SectionLabel("This phone")
        VSpace(10)
        ThisPhoneCard(state, onRename, onToggleBiometric, onRenew)

        VSpace(24)
        SectionLabel("Devices")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Column {
                NavRow(
                    Icons.Rounded.Devices,
                    "All devices",
                    "Every member of this identity · add or remove",
                    onDevices,
                )
                VbHairline(Modifier.padding(horizontal = 16.dp))
                NavRow(Icons.Rounded.AddCircle, "Add a device", "Sign in on another phone or computer", onAddDevice)
            }
        }

        VSpace(24)
        SectionLabel("Trusted sites")
        VSpace(10)
        SitesCard(state.trustedSites, onRevoke, onApprovalActivity)

        VSpace(24)
        SectionLabel("Recovery", color = VbColors.Amber)
        VSpace(10)
        RecoveryCard(state, onTestRecovery, onRecoveryBackup, onSplitShares) { confirmForget = true }

        VSpace(24)
        SectionLabel("Connections")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            NavRow(
                Icons.Rounded.Hub,
                "Pairing relay and push",
                connections,
                onConnections,
            )
        }

        VSpace(24)
        SectionLabel("About")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Column {
                AboutRow(Icons.Rounded.Info, "About Cruciform", "Version ${BuildConfig.VERSION_NAME}", onAbout)
                VbHairline(Modifier.padding(horizontal = 16.dp))
                AboutRow(
                    Icons.Rounded.Security,
                    "Security & protocol",
                    "Void-Which-Binds protocol · hardware-bound device keys",
                    onSecurity,
                )
                VbHairline(Modifier.padding(horizontal = 16.dp))
                AboutRow(Icons.Rounded.Code, "Open-source licenses", null, onLicenses)
            }
        }

        VSpace(28)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                Icons.Rounded.Shield,
                contentDescription = null,
                tint = VbColors.TextMuted,
                modifier = Modifier.size(16.dp),
            )
            HSpace(8)
            Text(
                "Your keys never leave your devices.",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
                textAlign = TextAlign.Center,
            )
        }
    }
}

/**
 * The identity fingerprint people compare between devices and with the recovery sheet,
 * with copy, and how this phone holds its key.
 */
@Composable
@OptIn(ExperimentalLayoutApi::class)
private fun IdentityCard(state: IdentityState.Active, onCopy: () -> Unit) {
    VbCard(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CruciformMark(size = 32.dp)
                HSpace(12)
                Text("IDENTITY KEY", style = MaterialTheme.typography.labelMedium, color = VbColors.TextMuted)
            }
            VSpace(10)
            IdentityFingerprint(state.identity.label, state.identity.fingerprint, onCopy = onCopy)
            VSpace(12)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (state.device.hardwareBacked) {
                    StatusPill("Hardware-backed", accent = VbColors.Mint, leadingIcon = Icons.Rounded.Shield)
                } else {
                    StatusPill("Software key", accent = VbColors.Amber, leadingIcon = Icons.Rounded.Memory)
                }
                if (state.identity.offlineVerifiable) {
                    StatusPill("Offline ready", accent = VbColors.Mint, leadingIcon = Icons.Rounded.Fingerprint)
                }
            }
        }
    }
}

/** This phone: its name, where its key lives, the biometric gate, and its membership. */
@Composable
private fun ThisPhoneCard(
    state: IdentityState.Active,
    onRename: () -> Unit,
    onToggleBiometric: (Boolean) -> Unit,
    onRenew: () -> Unit,
) {
    val device = state.device
    VbCard(modifier = Modifier.fillMaxWidth()) {
        Column {
            RowItem(
                title = "Device name",
                subtitle = "${device.name} · ${device.label}",
                onClick = onRename,
                leading = { FernIcon(Icons.Rounded.Smartphone) },
                trailing = {
                    IconButton(onClick = onRename) {
                        Icon(Icons.Rounded.Edit, contentDescription = "Rename", tint = VbColors.TextSecondary)
                    }
                },
            )
            VbHairline(Modifier.padding(horizontal = 16.dp))
            RowItem(
                title = when (device.backing) {
                    HardwareBacking.STRONGBOX -> "Hardware-backed (StrongBox)"
                    HardwareBacking.TEE -> "Hardware-backed (TEE)"
                    HardwareBacking.SOFTWARE -> "Software key (no secure element)"
                },
                subtitle = if (device.hardwareBacked) {
                    "The signing key can't be copied off this phone"
                } else {
                    "This phone has no secure element for the key"
                },
                leading = {
                    val accent = if (device.hardwareBacked) VbColors.Mint else VbColors.Amber
                    IconCircle(Icons.Rounded.Memory, tint = accent, background = accent.copy(alpha = 0.12f))
                },
            )
            VbHairline(Modifier.padding(horizontal = 16.dp))
            Row(
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconCircle(
                    Icons.Rounded.Fingerprint,
                    tint = VbColors.Mint,
                    background = VbColors.Mint.copy(alpha = 0.12f),
                )
                HSpace(14)
                Column(Modifier.weight(1f)) {
                    Text(
                        "Biometric approval",
                        style = MaterialTheme.typography.titleMedium,
                        color = VbColors.TextPrimary,
                    )
                    Text(
                        "Required for every signature",
                        style = MaterialTheme.typography.bodyMedium,
                        color = VbColors.TextSecondary,
                    )
                }
                Switch(
                    checked = state.biometricApproval,
                    onCheckedChange = onToggleBiometric,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = VbColors.OnMint,
                        checkedTrackColor = VbColors.Mint,
                        uncheckedTrackColor = VbColors.SurfaceElevated,
                    ),
                )
                HSpace(8)
                Icon(
                    Icons.Rounded.Lock,
                    contentDescription = null,
                    tint = VbColors.TextMuted,
                    modifier = Modifier.size(18.dp),
                )
            }
            VbHairline(Modifier.padding(horizontal = 16.dp))
            val membership = state.membership
            RowItem(
                title = "Membership",
                subtitle = when {
                    membership.lapsed -> "Lapsed · re-admit it from another device or your recovery secret"
                    else -> membership.renewsByLabel?.replaceFirstChar { it.uppercase() } ?: "Not a member"
                },
                leading = {
                    val accent = when {
                        membership.lapsed -> VbColors.Coral
                        membership.renewalDue -> VbColors.Amber
                        else -> VbColors.Fern
                    }
                    IconCircle(Icons.Rounded.Schedule, tint = accent, background = accent.copy(alpha = 0.12f))
                },
                trailing = if (membership.renewalDue && !membership.lapsed) {
                    { OutlineButton("Renew", onClick = onRenew, accent = VbColors.Amber) }
                } else {
                    null
                },
            )
        }
    }
}

/**
 * Every trusted site with its approval policy and Revoke, then the activity log. The
 * policy and Revoke share a line under the name, so neither squeezes the name or the
 * pill into wrapping on a phone-width card.
 */
@Composable
private fun SitesCard(sites: List<TrustedSite>, onRevoke: (TrustedSite) -> Unit, onApprovalActivity: () -> Unit) {
    VbCard(modifier = Modifier.fillMaxWidth()) {
        Column {
            sites.forEachIndexed { i, site ->
                Row(Modifier.fillMaxWidth().padding(16.dp)) {
                    SiteAvatar(site.accent, diameter = 40)
                    HSpace(14)
                    Column(Modifier.weight(1f)) {
                        Text(
                            site.domain,
                            style = MaterialTheme.typography.titleMedium,
                            color = VbColors.TextPrimary,
                        )
                        Text(
                            "${site.appName} · ${site.lastUsed}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = VbColors.TextSecondary,
                        )
                        VSpace(6)
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            PolicyPill(site)
                            Spacer(Modifier.weight(1f))
                            TextButton(onClick = { onRevoke(site) }) {
                                Text("Revoke", style = MaterialTheme.typography.labelLarge, color = VbColors.Coral)
                            }
                        }
                    }
                }
                if (i < sites.lastIndex) VbHairline(Modifier.padding(horizontal = 16.dp))
            }
            if (sites.isNotEmpty()) VbHairline(Modifier.padding(horizontal = 16.dp))
            NavRow(Icons.Rounded.History, "Approval activity", "Who you approved, and when", onApprovalActivity)
        }
    }
}

/** Test the written secret (any device); re-show, split or remove the copy (a device that keeps one). */
@Composable
private fun RecoveryCard(
    state: IdentityState.Active,
    onTestRecovery: () -> Unit,
    onRecoveryBackup: () -> Unit,
    onSplitShares: () -> Unit,
    onForget: () -> Unit,
) {
    VbCard(modifier = Modifier.fillMaxWidth()) {
        Column {
            // Any device can check the written secret: it only compares identities.
            AmberRow(
                Icons.Rounded.VpnKey,
                "Test recovery secret",
                when {
                    state.backup.drillDue -> "${state.backup.lastCheckedLabel} · check it again"
                    else -> state.backup.lastCheckedLabel ?: "Never checked on this device"
                },
                onTestRecovery,
            )
            // Only a device that keeps a copy can re-show or remove it.
            if (state.holdsRecoverySecret) {
                VbHairline(Modifier.padding(horizontal = 16.dp))
                // The biometric requirement sits in the subtitle: a trailing pill took
                // the title's width and wrapped it a letter or two per line on-device.
                AmberRow(
                    Icons.Rounded.VpnKey,
                    "Recovery backup",
                    "Re-show it · needs your fingerprint or face",
                    onRecoveryBackup,
                )
                VbHairline(Modifier.padding(horizontal = 16.dp))
                AmberRow(
                    Icons.Rounded.Groups,
                    "Split into shares",
                    "Give 2-of-3 pieces to people you trust",
                    onSplitShares,
                )
                VbHairline(Modifier.padding(horizontal = 16.dp))
                RowItem(
                    title = "Remove the copy on this phone",
                    subtitle = "Keep only what you wrote down",
                    onClick = onForget,
                    leading = {
                        IconCircle(
                            Icons.Rounded.Lock,
                            tint = VbColors.Coral,
                            background = VbColors.Coral.copy(alpha = 0.12f),
                        )
                    },
                    trailing = { Chevron(VbColors.Coral) },
                )
            }
        }
    }
}

/** A small pill showing a trusted site's approval policy: trusted (TOFU) vs. always-ask. */
@Composable
private fun PolicyPill(site: TrustedSite) {
    val trusted = site.policy == ApprovalPolicy.TrustedTofu
    StatusPill(
        text = when {
            site.pinnedAlwaysAsk -> "Always ask (pinned)"
            trusted -> "Trusted"
            else -> "Always ask"
        },
        accent = if (trusted) VbColors.Mint else VbColors.Amber,
        leadingIcon = if (trusted) Icons.Rounded.Shield else Icons.Rounded.Lock,
    )
}

@Composable
private fun NavRow(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    RowItem(
        title = title,
        subtitle = subtitle,
        onClick = onClick,
        leading = { FernIcon(icon) },
        trailing = { Chevron(VbColors.TextMuted) },
    )
}

@Composable
private fun AmberRow(icon: ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    RowItem(
        title = title,
        subtitle = subtitle,
        onClick = onClick,
        leading = { IconCircle(icon, tint = VbColors.Amber, background = VbColors.Amber.copy(alpha = 0.12f)) },
        trailing = { Chevron(VbColors.Amber) },
    )
}

@Composable
private fun FernIcon(icon: ImageVector) {
    IconCircle(icon, tint = VbColors.Fern, background = VbColors.Fern.copy(alpha = 0.12f))
}

@Composable
private fun AboutRow(icon: ImageVector, title: String, subtitle: String?, onClick: () -> Unit) {
    RowItem(
        title = title,
        subtitle = subtitle,
        onClick = onClick,
        leading = { IconCircle(icon, tint = VbColors.Mint, background = VbColors.SurfaceElevated) },
        trailing = { Chevron(VbColors.TextMuted) },
    )
}

@Composable
private fun Chevron(tint: Color) {
    Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null, tint = tint)
}
