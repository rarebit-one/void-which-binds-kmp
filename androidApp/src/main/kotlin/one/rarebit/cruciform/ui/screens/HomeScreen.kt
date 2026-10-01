package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.domain.DeviceInfo
import one.rarebit.cruciform.domain.HardwareBacking
import one.rarebit.cruciform.domain.Identity
import one.rarebit.cruciform.domain.MembershipHealth
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
import one.rarebit.cruciform.ui.components.WashCard
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType

/**
 * Home / identity dashboard: an identity-led hero, device protection, this device,
 * and the trusted sites.
 */
@Composable
fun HomeScreen(
    identity: Identity,
    device: DeviceInfo,
    trustedSites: List<TrustedSite>,
    membership: MembershipHealth,
    onRenew: () -> Unit,
    backupPending: Boolean,
    onCheckBackup: () -> Unit,
    onSettings: () -> Unit,
    onCopyIdentity: () -> Unit,
    onDevice: () -> Unit,
    onDevices: () -> Unit,
    onSite: (TrustedSite) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(ScreenPadding)
            .padding(top = 16.dp, bottom = 24.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Column {
                Text("CRUCIFORM", style = VbType.SectionLabel, color = VbColors.Mint)
                Text("Your identity", style = MaterialTheme.typography.titleLarge, color = VbColors.TextPrimary)
            }
            Spacer(Modifier.weight(1f))
            IconButton(onClick = onSettings) {
                Icon(Icons.Rounded.Settings, contentDescription = "Settings", tint = VbColors.TextSecondary)
            }
        }

        VSpace(14)
        VbCard(
            modifier = Modifier.fillMaxWidth(),
            color = VbColors.Surface,
            border = BorderStroke(1.dp, VbColors.Outline),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.verticalGradient(listOf(VbColors.SurfaceElevated, VbColors.Surface)),
                        RoundedCornerShape(18.dp),
                    ),
            ) {
                Canvas(Modifier.align(Alignment.TopEnd).size(width = 132.dp, height = 132.dp)) {
                    val step = 18.dp.toPx()
                    var x = 0f
                    while (x <= size.width) {
                        drawLine(
                            VbColors.Fern.copy(alpha = 0.12f),
                            Offset(x, 0f),
                            Offset(x, size.height),
                            strokeWidth = 1.dp.toPx(),
                        )
                        x += step
                    }
                    var y = 0f
                    while (y <= size.height) {
                        drawLine(
                            VbColors.Fern.copy(alpha = 0.12f),
                            Offset(0f, y),
                            Offset(size.width, y),
                            strokeWidth = 1.dp.toPx(),
                        )
                        y += step
                    }
                    drawRect(
                        color = VbColors.Amber.copy(alpha = 0.75f),
                        topLeft = Offset(size.width - 14.dp.toPx(), 12.dp.toPx()),
                        size = Size(3.dp.toPx(), 3.dp.toPx()),
                    )
                }
                CruciformMark(
                    size = 112.dp,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(top = 18.dp, end = 16.dp)
                        .graphicsLayer(alpha = 0.12f),
                )
                Column(Modifier.padding(18.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("IDENTITY KEY", style = VbType.SectionLabel, color = VbColors.TextMuted)
                        Spacer(Modifier.weight(1f))
                        if (identity.offlineVerifiable) {
                            StatusPill("OFFLINE READY", accent = VbColors.Mint, leadingIcon = Icons.Rounded.Fingerprint)
                        }
                    }
                    VSpace(10)
                    IdentityFingerprint(identity.label, identity.fingerprint, onCopy = onCopyIdentity)
                    VSpace(14)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(7.dp).clip(CircleShape).background(VbColors.Mint))
                        HSpace(8)
                        Text(
                            "Held on this device",
                            style = MaterialTheme.typography.labelMedium,
                            color = VbColors.TextSecondary,
                        )
                        Spacer(Modifier.weight(1f))
                        Text("YOUR KEY, YOURS", style = MaterialTheme.typography.labelSmall, color = VbColors.Mint)
                    }
                }
            }
        }

        VSpace(18)
        StrongBoxCard(device)

        if (backupPending) {
            VSpace(10)
            BackupCard(onCheckBackup)
        }

        if (membership.lapsed || membership.renewalDue) {
            VSpace(10)
            MembershipCard(membership, onRenew)
        }

        VSpace(26)
        SectionLabel("This device")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onDevice)
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(CircleShape)
                        .background(VbColors.FernWash),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        Icons.Rounded.Smartphone,
                        contentDescription = null,
                        tint = VbColors.Mint,
                        modifier = Modifier.size(26.dp),
                    )
                }
                HSpace(14)
                Column(Modifier.weight(1f)) {
                    Text(device.name, style = MaterialTheme.typography.titleMedium, color = VbColors.TextPrimary)
                    Text(device.label, style = VbType.Mono, color = VbColors.TextSecondary)
                    VSpace(6)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Rounded.Fingerprint,
                            contentDescription = null,
                            tint = VbColors.Mint,
                            modifier = Modifier.size(16.dp),
                        )
                        HSpace(6)
                        Text(
                            if (device.biometricRequired) "Biometric required" else "No biometric gate",
                            style = MaterialTheme.typography.bodyMedium,
                            color = VbColors.TextSecondary,
                        )
                    }
                }
                Icon(
                    Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                    contentDescription = null,
                    tint = VbColors.TextMuted,
                )
            }
        }
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            RowItem(
                title = "All devices",
                subtitle = "Members of this identity · add or remove",
                onClick = onDevices,
                leading = {
                    IconCircle(
                        Icons.Rounded.Devices,
                        tint = VbColors.Fern,
                        background = VbColors.Fern.copy(alpha = 0.12f),
                    )
                },
                trailing = {
                    Icon(
                        Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = null,
                        tint = VbColors.TextMuted,
                    )
                },
            )
        }

        VSpace(26)
        SectionLabel("Trusted sites", trailing = {
            Text("${trustedSites.size}", style = MaterialTheme.typography.labelMedium, color = VbColors.TextMuted)
        })
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Column {
                trustedSites.forEachIndexed { i, site ->
                    RowItem(
                        title = site.domain,
                        subtitle = "${site.appName} · ${site.lastUsed}",
                        onClick = { onSite(site) },
                        leading = { SiteAvatar(site.accent) },
                        trailing = {
                            Icon(
                                Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                                contentDescription = null,
                                tint = VbColors.TextMuted,
                            )
                        },
                    )
                    if (i < trustedSites.lastIndex) VbHairline(Modifier.padding(start = 74.dp))
                }
            }
        }
    }
}

/**
 * Shown until the recovery secret written down at creation has been checked back
 * (void-which-binds-go ADR-0010): an unchecked backup is found to be wrong only when needed.
 */
@Composable
private fun BackupCard(onCheck: () -> Unit) {
    WashCard(accent = VbColors.Amber, wash = VbColors.AmberWash, modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Rounded.VpnKey,
                    contentDescription = null,
                    tint = VbColors.Amber,
                    modifier = Modifier.size(28.dp),
                )
                HSpace(14)
                Column(Modifier.weight(1f)) {
                    Text(
                        "Check your recovery secret",
                        style = MaterialTheme.typography.titleMedium,
                        color = VbColors.TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "You haven't confirmed what you wrote down. It's the only way back if you lose your devices.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = VbColors.TextSecondary,
                    )
                }
            }
            VSpace(10)
            OutlineButton(
                "Check it now",
                onClick = onCheck,
                accent = VbColors.Amber,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/**
 * Shown only when this device needs attention: inside the renewal window (renew now,
 * while the device can still renew itself) or already lapsed (only another device or
 * the recovery secret can re-admit it).
 */
@Composable
private fun MembershipCard(membership: MembershipHealth, onRenew: () -> Unit) {
    val accent = if (membership.lapsed) VbColors.Coral else VbColors.Amber
    WashCard(accent = accent, wash = VbColors.AmberWash, modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Schedule, contentDescription = null, tint = accent, modifier = Modifier.size(28.dp))
                HSpace(14)
                Column(Modifier.weight(1f)) {
                    Text(
                        if (membership.lapsed) "This device has lapsed" else "Renew this device",
                        style = MaterialTheme.typography.titleMedium,
                        color = VbColors.TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        if (membership.lapsed) {
                            "It can't sign in until it's re-admitted from another device or your recovery secret."
                        } else {
                            "Its membership ${membership.renewsByLabel ?: "expires soon"}. Renewing keeps it signed in."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = VbColors.TextSecondary,
                    )
                }
            }
            if (!membership.lapsed) {
                VSpace(10)
                OutlineButton("Renew now", onClick = onRenew, accent = accent, modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

@Composable
private fun StrongBoxCard(device: DeviceInfo) {
    val label = when (device.backing) {
        HardwareBacking.STRONGBOX -> "Hardware-backed (StrongBox)"
        HardwareBacking.TEE -> "Hardware-backed (TEE)"
        HardwareBacking.SOFTWARE -> "Software key (no secure element)"
    }
    val accent = if (device.hardwareBacked) VbColors.Mint else VbColors.Amber
    WashCard(accent = accent, wash = VbColors.MintWash, modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Rounded.Memory, contentDescription = null, tint = accent, modifier = Modifier.size(44.dp))
            HSpace(14)
            Column(Modifier.weight(1f)) {
                Text(
                    label,
                    style = MaterialTheme.typography.titleMedium,
                    color = VbColors.TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    if (device.biometricRequired) "Signing key requires biometrics" else "Signing key on this device",
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextSecondary,
                )
                VSpace(8)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Dot(accent)
                    HSpace(6)
                    Text(
                        if (device.hardwareBacked) "Protected" else "Not hardware-backed",
                        style = MaterialTheme.typography.labelMedium,
                        color = accent,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
        }
    }
}

@Composable
private fun Dot(color: Color, size: Int = 8) {
    Box(
        Modifier
            .size(size.dp)
            .clip(CircleShape)
            .background(color),
    )
}
