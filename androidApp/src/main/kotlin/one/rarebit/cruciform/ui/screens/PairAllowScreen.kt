package one.rarebit.cruciform.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.DangerButton
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.WashCard
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType

/**
 * The SAME-PHONE one-tap approval (ADR-0008). It replaces the SAS-compare screen when —
 * and only when — the relying-party app on this phone reported its own device key and
 * SAS over the local `cruciform://pair-joined` intent and both matched what the relay
 * revealed. The comparison a human would have made across two apps has already been
 * made, by the two apps, over a channel the relay cannot reach; what is left is the
 * question only a person can answer.
 *
 * So there is exactly one question and no code on screen. Cross-device pairing keeps
 * [PairVerifyScreen] and its 7-digit comparison — there is no second channel there.
 */
@Composable
fun PairAllowScreen(
    /** The RP's human name, e.g. "heyarr". */
    appName: String,
    onAllow: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
    /** The RP's launcher icon, when the system could give us one. */
    appIcon: Drawable? = null,
    /** True while the add is being signed and delivered — the buttons go away. */
    busy: Boolean = false,
) {
    SecureScreen()
    Column(modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
        AppTopBar(title = "Add a device", onBack = onCancel)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 24.dp)) {
            Text("ON THIS PHONE", style = VbType.SectionLabel, color = VbColors.Mint)
            VSpace(20)

            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                AppGlyph(appIcon)
                HSpace(16)
                Column {
                    Text(appName, style = MaterialTheme.typography.headlineSmall, color = VbColors.TextPrimary)
                    Text("on this phone", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary)
                }
            }

            VSpace(28)
            Text(
                "Allow $appName to act as you?",
                style = MaterialTheme.typography.headlineMedium,
                color = VbColors.TextPrimary,
            )
            VSpace(8)
            Text(
                "It becomes one of your devices: it can sign in as you and hold your data, until you remove it in Manage → Devices.",
                style = MaterialTheme.typography.bodyLarge,
                color = VbColors.TextSecondary,
            )

            VSpace(20)
            WashCard(accent = VbColors.Mint, wash = VbColors.Surface, modifier = Modifier.fillMaxWidth()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Rounded.VerifiedUser,
                        contentDescription = null,
                        tint = VbColors.Mint,
                        modifier = Modifier.size(28.dp),
                    )
                    HSpace(12)
                    Text(
                        "Both apps are on this phone, so they checked each other's keys directly — there is no code for you to compare.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = VbColors.TextSecondary,
                    )
                }
            }

            VSpace(24)
            if (busy) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), color = VbColors.Mint)
                    HSpace(12)
                    Text("Authorising…", style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary)
                }
            } else {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    DangerButton(
                        "No, cancel",
                        onClick = onCancel,
                        leadingIcon = Icons.Rounded.Close,
                        modifier = Modifier.weight(1f),
                    )
                    PrimaryButton(
                        "Allow",
                        onClick = onAllow,
                        leadingIcon = Icons.Rounded.Check,
                        fill = VbColors.Mint,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            VSpace(12)
            Text(
                "Biometric confirmation required",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/** The RP's own icon when the system gave us one; a neutral phone glyph otherwise. */
@Composable
private fun AppGlyph(icon: Drawable?) {
    Box(
        modifier = Modifier.size(64.dp).clip(CircleShape).background(VbColors.SurfaceElevated),
        contentAlignment = Alignment.Center,
    ) {
        if (icon != null) {
            val bitmap = remember(icon) { runCatching { icon.toBitmap(112, 112).asImageBitmap() }.getOrNull() }
            if (bitmap != null) {
                Image(bitmap = bitmap, contentDescription = null, modifier = Modifier.size(40.dp))
                return@Box
            }
        }
        Icon(Icons.Rounded.Smartphone, contentDescription = null, tint = VbColors.Mint, modifier = Modifier.size(30.dp))
    }
}
