// Compose components are PascalCase by convention; layout spacing is literal dp.
// A screen reads top to bottom as one composable, and its callbacks are hoisted one per action.
@file:Suppress(
    "FunctionNaming",
    "MagicNumber",
    "ktlint:standard:function-naming",
    "LongMethod",
    "LongParameterList",
)

package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.domain.ApprovalActivity
import one.rarebit.cruciform.domain.HomeSummary
import one.rarebit.cruciform.domain.HomeSummary.Attention
import one.rarebit.cruciform.domain.HomeSummary.Status
import one.rarebit.cruciform.domain.IdentityState
import one.rarebit.cruciform.domain.MembershipHealth
import one.rarebit.cruciform.ui.components.CruciformMark
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.RowItem
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SectionLabel
import one.rarebit.cruciform.ui.components.SiteAvatar
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.VbHairline
import one.rarebit.cruciform.ui.components.WashCard
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType

/** How many recent sign-ins Home shows before "See all". */
private const val RECENT_SHOWN = 3

/**
 * Home: the everyday view. It answers "can I sign in?" in plain words, offers the scan,
 * raises only what needs the person ([HomeSummary]), and lists recent sign-ins and the
 * sites this identity uses. Fingerprints, key backing, devices and endpoints are one tap
 * away in Manage; nothing here is a control that changes the identity.
 */
@Composable
fun HomeScreen(
    state: IdentityState.Active,
    recent: List<ApprovalActivity>,
    onScan: () -> Unit,
    onRenew: () -> Unit,
    onCheckBackup: () -> Unit,
    onActivity: () -> Unit,
    onManage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val summary = HomeSummary.of(state)
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(ScreenPadding)
            .padding(top = 16.dp, bottom = 24.dp),
    ) {
        Text("CRUCIFORM", style = VbType.SectionLabel, color = VbColors.Mint)
        VSpace(14)
        StatusHero(summary, state, onScan)

        summary.attention.forEach { item ->
            VSpace(10)
            when (item) {
                Attention.DEVICE_LAPSED, Attention.RENEW_DEVICE -> MembershipCard(state.membership, onRenew)
                Attention.CHECK_BACKUP -> BackupCard(onCheckBackup)
                Attention.SOFTWARE_KEY -> SoftwareKeyCard(onManage)
            }
        }

        VSpace(26)
        SectionLabel("Recent sign-ins", trailing = {
            if (recent.isNotEmpty()) {
                Text(
                    "See all",
                    style = MaterialTheme.typography.labelMedium,
                    color = VbColors.Mint,
                    modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable(onClick = onActivity).padding(4.dp),
                )
            }
        })
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            if (recent.isEmpty()) {
                Text(
                    "Sign-ins you approve or deny show up here.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextMuted,
                    modifier = Modifier.padding(16.dp),
                )
            } else {
                Column {
                    val shown = recent.take(RECENT_SHOWN)
                    shown.forEachIndexed { i, entry ->
                        ActivityRow(entry)
                        if (i < shown.lastIndex) VbHairline(Modifier.padding(horizontal = 16.dp))
                    }
                }
            }
        }

        if (state.trustedSites.isNotEmpty()) {
            VSpace(26)
            SectionLabel("Sites you use", trailing = {
                Text(
                    "${state.trustedSites.size}",
                    style = MaterialTheme.typography.labelMedium,
                    color = VbColors.TextMuted,
                )
            })
            VSpace(10)
            VbCard(modifier = Modifier.fillMaxWidth()) {
                Column {
                    state.trustedSites.forEachIndexed { i, site ->
                        RowItem(
                            title = site.domain,
                            subtitle = "${site.appName} · ${site.lastUsed}",
                            leading = { SiteAvatar(site.accent) },
                        )
                        if (i < state.trustedSites.lastIndex) VbHairline(Modifier.padding(start = 74.dp))
                    }
                }
            }
        }
    }
}

/**
 * The verdict and the one action: a headline saying whether this phone can sign in, how
 * the key is kept in a phrase, and Scan. A device that cannot sign in is not offered the
 * scan; its card below says how to come back.
 */
@Composable
private fun StatusHero(summary: HomeSummary, state: IdentityState.Active, onScan: () -> Unit) {
    val (eyebrow, accent) = when (summary.status) {
        Status.READY -> "READY" to VbColors.Mint
        Status.NEEDS_ATTENTION -> "READY · ${needsYou(summary.attention.size)}" to VbColors.Amber
        Status.CANNOT_SIGN_IN -> "CAN'T SIGN IN" to VbColors.Coral
    }
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
            HeroGrid(Modifier.align(Alignment.TopEnd))
            CruciformMark(
                size = 112.dp,
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(top = 18.dp, end = 16.dp)
                    .graphicsLayer(alpha = 0.12f),
            )
            Column(Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Dot(accent)
                    HSpace(8)
                    Text(eyebrow, style = VbType.SectionLabel, color = accent)
                }
                VSpace(10)
                Text(
                    if (summary.status == Status.CANNOT_SIGN_IN) "This phone can't sign in" else "Ready to sign in",
                    style = MaterialTheme.typography.headlineSmall,
                    color = VbColors.TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                )
                VSpace(6)
                Text(
                    if (summary.status == Status.CANNOT_SIGN_IN) {
                        "It needs to be let back in from another of your devices, or with your recovery secret."
                    } else {
                        "Scan the code on a sign-in page, or approve the request when this phone asks."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextSecondary,
                )
                if (summary.status != Status.CANNOT_SIGN_IN) {
                    VSpace(16)
                    PrimaryButton(
                        "Scan to sign in",
                        onClick = onScan,
                        leadingIcon = Icons.Rounded.QrCodeScanner,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (state.device.hardwareBacked) {
                    VSpace(14)
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Dot(VbColors.Mint, size = 7)
                        HSpace(8)
                        Text(
                            if (state.device.biometricRequired) {
                                "Your key stays on this phone, behind your fingerprint or face"
                            } else {
                                "Your key stays on this phone"
                            },
                            style = MaterialTheme.typography.labelMedium,
                            color = VbColors.TextSecondary,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        }
    }
}

private fun needsYou(count: Int) = if (count == 1) "1 THING NEEDS YOU" else "$count THINGS NEED YOU"

/** The faint grid behind the hero's mark, carried over from the identity card it replaces. */
@Composable
private fun HeroGrid(modifier: Modifier) {
    Canvas(modifier.size(width = 132.dp, height = 132.dp)) {
        val step = 18.dp.toPx()
        var x = 0f
        while (x <= size.width) {
            drawLine(VbColors.Fern.copy(alpha = 0.12f), Offset(x, 0f), Offset(x, size.height), 1.dp.toPx())
            x += step
        }
        var y = 0f
        while (y <= size.height) {
            drawLine(VbColors.Fern.copy(alpha = 0.12f), Offset(0f, y), Offset(size.width, y), 1.dp.toPx())
            y += step
        }
        drawRect(
            color = VbColors.Amber.copy(alpha = 0.75f),
            topLeft = Offset(size.width - 14.dp.toPx(), 12.dp.toPx()),
            size = Size(3.dp.toPx(), 3.dp.toPx()),
        )
    }
}

/**
 * Shown until the recovery secret written down at creation has been checked back
 * (void-which-binds-go ADR-0010): an unchecked backup is found to be wrong only when needed.
 */
@Composable
private fun BackupCard(onCheck: () -> Unit) {
    AttentionCard(
        icon = Icons.Rounded.VpnKey,
        accent = VbColors.Amber,
        title = "Check your recovery secret",
        body = "You haven't confirmed what you wrote down. It's the only way back if you lose your devices.",
        action = "Check it now",
        onAction = onCheck,
    )
}

/**
 * Shown only when this device needs attention: inside the renewal window (renew now,
 * while the device can still renew itself) or already lapsed (only another device or
 * the recovery secret can re-admit it).
 */
@Composable
private fun MembershipCard(membership: MembershipHealth, onRenew: () -> Unit) {
    if (membership.lapsed) {
        AttentionCard(
            icon = Icons.Rounded.Schedule,
            accent = VbColors.Coral,
            title = "This device has lapsed",
            body = "It can't sign in until it's re-admitted from another device or your recovery secret.",
        )
    } else {
        AttentionCard(
            icon = Icons.Rounded.Schedule,
            accent = VbColors.Amber,
            title = "Renew this device",
            body = "Its membership ${membership.renewsByLabel ?: "expires soon"}. Renewing keeps it signed in.",
            action = "Renew now",
            onAction = onRenew,
        )
    }
}

/** This phone has no secure element for the key: signing works, but the person should know. */
@Composable
private fun SoftwareKeyCard(onDetails: () -> Unit) {
    AttentionCard(
        icon = Icons.Rounded.Memory,
        accent = VbColors.Amber,
        title = "Your key isn't in secure hardware",
        body = "This phone has no secure chip for it, so it is kept in software. Sign-in still works.",
        action = "See details",
        onAction = onDetails,
    )
}

@Composable
private fun AttentionCard(
    icon: ImageVector,
    accent: Color,
    title: String,
    body: String,
    action: String? = null,
    onAction: () -> Unit = {},
) {
    WashCard(accent = accent, wash = VbColors.AmberWash, modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, contentDescription = null, tint = accent, modifier = Modifier.size(28.dp))
                HSpace(14)
                Column(Modifier.weight(1f)) {
                    Text(
                        title,
                        style = MaterialTheme.typography.titleMedium,
                        color = VbColors.TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(body, style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary)
                }
            }
            if (action != null) {
                VSpace(10)
                OutlineButton(action, onClick = onAction, accent = accent, modifier = Modifier.fillMaxWidth())
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
