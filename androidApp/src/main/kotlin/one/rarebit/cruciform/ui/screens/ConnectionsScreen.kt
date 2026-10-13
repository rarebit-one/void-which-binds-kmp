// Compose components are PascalCase by convention; layout spacing is literal dp.
// The endpoint editor moved here unchanged from Settings, where these were baselined.
@file:Suppress(
    "FunctionNaming",
    "MagicNumber",
    "ktlint:standard:function-naming",
    "LongMethod",
    "LongParameterList",
    "CyclomaticComplexMethod",
)

package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.platform.NotifyConfig
import one.rarebit.cruciform.platform.RelayConfig
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.IconCircle
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SectionLabel
import one.rarebit.cruciform.ui.components.StatusPill
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * Manage → **Connections**: the two servers this phone dials, for a self-hosted setup.
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
 * hatch that is not a rebuild. They sit here rather than in Manage itself because
 * nobody needs them day to day.
 */
@Composable
fun ConnectionsScreen(
    onBack: () -> Unit,
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
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        AppTopBar(title = "Connections", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 28.dp)) {
            Text(
                "Leave these alone unless you run your own servers.",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
            )

            VSpace(20)
            SectionLabel("Pairing")
            VSpace(10)
            VbCard(modifier = Modifier.fillMaxWidth()) {
                EndpointField(
                    title = "Pairing relay",
                    description = "Where this phone mints Add-a-device invites. " +
                        "A device joining an invite uses the relay in the invite.",
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
                    description = "Where this phone registers to be woken for a login. It carries only " +
                        "the same opaque tuple a QR does — never a key or a challenge.",
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
                ?: if (defaultUrl.isBlank()) {
                    "No default in this build — enter a URL to use one."
                } else {
                    "Default: $defaultUrl"
                },
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
