package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Groups
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.BuildConfig
import one.rarebit.cruciform.domain.IdentityState
import one.rarebit.cruciform.domain.TrustedSite
import one.rarebit.cruciform.platform.NotifyConfig
import one.rarebit.cruciform.platform.RelayConfig
import one.rarebit.cruciform.ui.components.CruciformMark
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.IconCircle
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.RowItem
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SectionLabel
import one.rarebit.cruciform.ui.components.SiteAvatar
import one.rarebit.cruciform.ui.components.StatusPill
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.VbHairline
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType
import one.rarebit.voidwhichbinds.policy.ApprovalPolicy

/**
 * Settings (Mockup 8): identity header, device, pairing relay, trusted sites, recovery,
 * about.
 *
 * The **Pairing relay** field edits where THIS phone mints "Add a device" invites
 * ([relayUrl], the persisted value; [relayIsDefault] when no override is stored).
 * [onSaveRelay] validates + persists and returns the verdict so an invalid URL is
 * shown inline and never written; [onResetRelay] drops the override. [focusRelay]
 * is set when the user arrived via the error dialog's "Change relay" — the field
 * takes focus (and scrolls into view) once, then [onRelayFocused] clears the flag.
 *
 * The push plane is configured the same way ([notifyUrl], [notifyIsDefault],
 * [onSaveNotify], [onResetNotify]) — both are endpoint bases this phone dials, and
 * both were shipped pointing at names that do not resolve, so both need an escape
 * hatch that is not a rebuild.
 */
@Composable
fun SettingsScreen(
    state: IdentityState.Active,
    onRename: () -> Unit,
    onToggleBiometric: (Boolean) -> Unit,
    onRevoke: (TrustedSite) -> Unit,
    onManageSites: () -> Unit,
    onRecoveryBackup: () -> Unit,
    onTestRecovery: () -> Unit,
    onForgetRecovery: () -> Unit,
    onSplitShares: () -> Unit,
    onApprovalActivity: () -> Unit,
    onDevices: () -> Unit,
    onAbout: () -> Unit,
    onSecurity: () -> Unit,
    onLicenses: () -> Unit,
    modifier: Modifier = Modifier,
    relayUrl: String = RelayConfig.DEFAULT_RELAY,
    relayIsDefault: Boolean = true,
    onSaveRelay: (String) -> RelayConfig.Validation = { RelayConfig.validate(it) },
    onResetRelay: () -> Unit = {},
    focusRelay: Boolean = false,
    onRelayFocused: () -> Unit = {},
    notifyUrl: String = NotifyConfig.DEFAULT_NOTIFY,
    notifyIsDefault: Boolean = true,
    onSaveNotify: (String) -> RelayConfig.Validation = { NotifyConfig.validate(it) },
    onResetNotify: () -> Unit = {},
    // The text in each field, hoisted so an entered-but-unsaved URL survives process
    // death (the Settings ViewModel keeps it in its SavedStateHandle).
    relayDraft: String = relayUrl,
    onRelayDraftChange: (String) -> Unit = {},
    notifyDraft: String = notifyUrl,
    onNotifyDraftChange: (String) -> Unit = {},
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
        Text("Settings", style = MaterialTheme.typography.headlineLarge, color = VbColors.TextPrimary)

        VSpace(20)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                CruciformMark(size = 40.dp)
                HSpace(14)
                Column(Modifier.weight(1f)) {
                    Text(
                        "${state.identity.label} · ${state.identity.fingerprint}",
                        style = VbType.Mono,
                        color = VbColors.TextPrimary,
                    )
                    VSpace(8)
                    StatusPill("Hardware-backed", accent = VbColors.Mint, leadingIcon = Icons.Rounded.Shield)
                }
            }
        }

        VSpace(24)
        SectionLabel("Device")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Column {
                RowItem(
                    title = "Device name",
                    subtitle = state.device.name,
                    onClick = onRename,
                    leading = {
                        IconCircle(
                            Icons.Rounded.Fingerprint,
                            tint = VbColors.Fern,
                            background = VbColors.Fern.copy(alpha = 0.12f),
                        )
                    },
                    trailing = {
                        IconButton(onClick = onRename) {
                            Icon(Icons.Rounded.Edit, contentDescription = "Rename", tint = VbColors.TextSecondary)
                        }
                    },
                )
                VbHairline(Modifier.padding(horizontal = 16.dp))
                RowItem(
                    title = "Devices",
                    subtitle = "Every member of this identity · add or remove",
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
            }
        }

        VSpace(24)
        SectionLabel("Pairing")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            EndpointField(
                title = "Pairing relay",
                description = "Where this phone mints Add-a-device invites. A device joining an invite uses the relay in the invite.",
                fieldLabel = "Relay URL",
                url = relayUrl,
                draft = relayDraft,
                onDraftChange = onRelayDraftChange,
                defaultUrl = RelayConfig.DEFAULT_RELAY,
                isDefault = relayIsDefault,
                validate = RelayConfig::validate,
                onSave = onSaveRelay,
                onReset = onResetRelay,
                focus = focusRelay,
                onFocused = onRelayFocused,
            )
        }

        VSpace(24)
        SectionLabel("Push")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            EndpointField(
                title = "Push plane",
                description = "Where this phone registers to be woken for a login. It carries only the same opaque tuple a QR does — never a key or a challenge.",
                fieldLabel = "Push plane URL",
                url = notifyUrl,
                draft = notifyDraft,
                onDraftChange = onNotifyDraftChange,
                defaultUrl = NotifyConfig.DEFAULT_NOTIFY,
                isDefault = notifyIsDefault,
                validate = NotifyConfig::validate,
                onSave = onSaveNotify,
                onReset = onResetNotify,
                focus = false,
                onFocused = {},
            )
        }

        VSpace(24)
        SectionLabel("Trusted sites")
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Column {
                state.trustedSites.take(2).forEachIndexed { i, site ->
                    Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
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
                            PolicyPill(site)
                        }
                        OutlineButton("Revoke", onClick = { onRevoke(site) }, accent = VbColors.Coral)
                    }
                    if (i == 0) VbHairline(Modifier.padding(horizontal = 16.dp))
                }
                VbHairline(Modifier.padding(horizontal = 16.dp))
                RowItem(
                    title = "Approval activity",
                    subtitle = "Who you approved, and when",
                    onClick = onApprovalActivity,
                    leading = {
                        IconCircle(
                            Icons.Rounded.History,
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
                VbHairline(Modifier.padding(horizontal = 16.dp))
                RowItem(
                    title = "Manage all ${state.trustedSites.size} trusted sites",
                    titleColor = VbColors.Mint,
                    onClick = onManageSites,
                    trailing = {
                        Icon(
                            Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                            contentDescription = null,
                            tint = VbColors.Mint,
                        )
                    },
                )
            }
        }

        VSpace(24)
        SectionLabel("Recovery", color = VbColors.Amber)
        VSpace(10)
        VbCard(modifier = Modifier.fillMaxWidth()) {
            Column {
                // Any device can check the written secret: it only compares identities.
                RowItem(
                    title = "Test recovery secret",
                    subtitle = when {
                        state.backup.drillDue -> "${state.backup.lastCheckedLabel} · check it again"
                        else -> state.backup.lastCheckedLabel ?: "Never checked on this device"
                    },
                    onClick = onTestRecovery,
                    leading = {
                        IconCircle(
                            Icons.Rounded.VpnKey,
                            tint = VbColors.Amber,
                            background = VbColors.Amber.copy(alpha = 0.12f),
                        )
                    },
                    trailing = { Chevron(VbColors.Amber) },
                )
                // Only a device that keeps a copy can re-show or remove it.
                if (state.holdsRecoverySecret) {
                    VbHairline(Modifier.padding(horizontal = 16.dp))
                    // The biometric requirement sits in the subtitle: a trailing pill took
                    // the title's width and wrapped it a letter or two per line on-device.
                    RowItem(
                        title = "Recovery backup",
                        subtitle = "Re-show it · needs your fingerprint or face",
                        onClick = onRecoveryBackup,
                        leading = {
                            IconCircle(
                                Icons.Rounded.VpnKey,
                                tint = VbColors.Amber,
                                background = VbColors.Amber.copy(alpha = 0.12f),
                            )
                        },
                        trailing = { Chevron(VbColors.Amber) },
                    )
                    VbHairline(Modifier.padding(horizontal = 16.dp))
                    RowItem(
                        title = "Split into shares",
                        subtitle = "Give 2-of-3 pieces to people you trust",
                        onClick = onSplitShares,
                        leading = {
                            IconCircle(
                                Icons.Rounded.Groups,
                                tint = VbColors.Amber,
                                background = VbColors.Amber.copy(alpha = 0.12f),
                            )
                        },
                        trailing = { Chevron(VbColors.Amber) },
                    )
                    VbHairline(Modifier.padding(horizontal = 16.dp))
                    RowItem(
                        title = "Remove the copy on this phone",
                        subtitle = "Keep only what you wrote down",
                        onClick = { confirmForget = true },
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
 * One endpoint-base editor — the "Pairing relay" and the "Push plane" are the same
 * control over different settings, so they are one composable rather than two that
 * drift. The [draft] text is hoisted to the caller (seeded from the persisted [url] and
 * re-seeded on a Save or a Reset); [validate] runs inline as the user types, and Save
 * writes only a `Valid` verdict. Nothing here talks to the network: the relay is
 * dialled at invite time and the plane at push-registration time.
 */
@Composable
private fun EndpointField(
    title: String,
    description: String,
    fieldLabel: String,
    url: String,
    draft: String,
    onDraftChange: (String) -> Unit,
    defaultUrl: String,
    isDefault: Boolean,
    validate: (String) -> RelayConfig.Validation,
    onSave: (String) -> RelayConfig.Validation,
    onReset: () -> Unit,
    focus: Boolean,
    onFocused: () -> Unit,
) {
    var saveError by remember { mutableStateOf<String?>(null) }
    val focusRequester = remember { FocusRequester() }
    val verdict = validate(draft)
    val liveError = (verdict as? RelayConfig.Validation.Invalid)?.reason
    val dirty = (verdict as? RelayConfig.Validation.Valid)?.url != url
    val error = saveError ?: liveError.takeIf { dirty }

    LaunchedEffect(focus) {
        if (focus) {
            focusRequester.requestFocus()
            onFocused()
        }
    }

    Column(Modifier.padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconCircle(Icons.Rounded.Hub, tint = VbColors.Fern, background = VbColors.Fern.copy(alpha = 0.12f))
            HSpace(14)
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, color = VbColors.TextPrimary)
                Text(
                    description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextSecondary,
                )
            }
            HSpace(8)
            // No build default and no override: the field is empty and nothing is dialled.
            val notSet = isDefault && defaultUrl.isBlank()
            StatusPill(
                text = when {
                    notSet -> "Not set"
                    isDefault -> "Default"
                    else -> "Custom"
                },
                accent = if (isDefault && !notSet) VbColors.Mint else VbColors.Amber,
                leadingIcon = Icons.Rounded.Hub,
            )
        }
        VSpace(14)
        OutlinedTextField(
            value = draft,
            onValueChange = {
                onDraftChange(it)
                saveError = null
            },
            modifier = Modifier.fillMaxWidth().focusRequester(focusRequester),
            label = { Text(fieldLabel) },
            placeholder = { Text(defaultUrl.ifBlank { "https://" }) },
            isError = error != null,
            singleLine = true,
            textStyle = TextStyle(fontFamily = FontFamily.Monospace),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.None,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Uri,
            ),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = VbColors.Mint,
                unfocusedBorderColor = VbColors.Outline,
                cursorColor = VbColors.Mint,
                focusedLabelColor = VbColors.Mint,
            ),
        )
        VSpace(8)
        Text(
            error
                ?: if (defaultUrl.isBlank()) "No default in this build — enter a URL to use one." else "Default: $defaultUrl",
            style = MaterialTheme.typography.bodyMedium,
            color = if (error != null) VbColors.Coral else VbColors.TextMuted,
        )
        VSpace(12)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            PrimaryButton(
                "Save",
                onClick = {
                    when (val result = onSave(draft)) {
                        is RelayConfig.Validation.Valid -> {
                            saveError = null
                            onDraftChange(result.url)
                        }

                        is RelayConfig.Validation.Invalid -> saveError = result.reason
                    }
                },
                enabled = dirty && liveError == null,
                modifier = Modifier.weight(1f),
            )
            OutlineButton(
                if (defaultUrl.isBlank()) "Clear" else "Reset to default",
                onClick = {
                    saveError = null
                    onReset()
                    onDraftChange(defaultUrl)
                },
                enabled = !isDefault || draft != defaultUrl,
                accent = VbColors.TextSecondary,
                modifier = Modifier.weight(1f),
            )
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
private fun AboutRow(icon: ImageVector, title: String, subtitle: String?, onClick: () -> Unit) {
    RowItem(
        title = title,
        subtitle = subtitle,
        onClick = onClick,
        leading = { IconCircle(icon, tint = VbColors.Mint, background = VbColors.SurfaceElevated) },
        trailing = {
            Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null, tint = VbColors.TextMuted)
        },
    )
}

@Composable
private fun Chevron(tint: Color) {
    Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null, tint = tint)
}
