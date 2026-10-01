package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.FlashlightOn
import androidx.compose.material.icons.rounded.Keyboard
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.OutlineButton
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.scan.QrScanner
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * QR scanner (Mockup 3): a live camera viewfinder that decodes Void-Which-Binds login and
 * pairing codes, and the recovery sheet's code, with a manual-entry fallback. The
 * scanned payload is handed up via [onCode]; the nav layer parses it and routes it.
 *
 * A code the nav layer refuses comes back as [rejection], shown with "Scan again"
 * ([onRetry], which re-arms the camera through [rescanKey]). [forRecoverySecret] is the
 * scanner the Restore and drill fields open: its copy asks for the recovery sheet.
 * The camera can see a recovery sheet in either mode, so screenshots are blocked.
 */
@Composable
fun ScanScreen(
    onClose: () -> Unit,
    onCode: (String) -> Unit,
    onEnterManually: () -> Unit,
    modifier: Modifier = Modifier,
    forRecoverySecret: Boolean = false,
    rejection: String? = null,
    onRetry: () -> Unit = {},
    rescanKey: Int = 0,
) {
    SecureScreen()
    Box(modifier = modifier.fillMaxSize().background(VbColors.Background)) {
        QrScanner(
            onQr = onCode,
            rescanKey = rescanKey,
            modifier = Modifier.fillMaxSize(),
            noPermission = {
                Column(
                    modifier = Modifier.fillMaxSize().padding(32.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        "Camera access is needed to scan Voidbind codes.",
                        style = MaterialTheme.typography.titleMedium,
                        color = VbColors.TextPrimary,
                        textAlign = TextAlign.Center,
                    )
                    VSpace(16)
                    OutlineButton("Enter code instead", onClick = onEnterManually, accent = VbColors.Mint)
                }
            },
        )

        // Top bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(VbColors.Background.copy(alpha = 0.55f))
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onClose) {
                Icon(Icons.Rounded.Close, contentDescription = "Close", tint = VbColors.TextPrimary)
            }
            Spacer(Modifier.weight(1f))
            Text(
                if (forRecoverySecret) "Scan recovery sheet" else "Scan QR code",
                style = MaterialTheme.typography.titleMedium,
                color = VbColors.TextPrimary,
            )
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { /* torch toggle: wired with the camera controller later */ }) {
                Icon(Icons.Rounded.FlashlightOn, contentDescription = "Torch", tint = VbColors.TextPrimary)
            }
        }

        // Viewfinder
        Box(
            modifier = Modifier
                .align(Alignment.Center)
                .padding(horizontal = 40.dp)
                .fillMaxWidth()
                .aspectRatio(1f),
            contentAlignment = Alignment.Center,
        ) {
            androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
                val corner = size.minDimension * 0.14f
                val sw = 8f
                val stroke = Stroke(width = sw)
                fun l(x1: Float, y1: Float, x2: Float, y2: Float) =
                    drawLine(VbColors.Fern, Offset(x1, y1), Offset(x2, y2), strokeWidth = sw)
                // corner brackets
                l(0f, 0f, corner, 0f)
                l(0f, 0f, 0f, corner)
                l(size.width, 0f, size.width - corner, 0f)
                l(size.width, 0f, size.width, corner)
                l(0f, size.height, corner, size.height)
                l(0f, size.height, 0f, size.height - corner)
                l(size.width, size.height, size.width - corner, size.height)
                l(size.width, size.height, size.width, size.height - corner)
                // scan line
                drawLine(
                    VbColors.Mint,
                    Offset(0f, size.height / 2f),
                    Offset(size.width, size.height / 2f),
                    strokeWidth = 4f,
                )
            }
        }

        // Bottom controls
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            if (rejection != null) {
                Text(
                    rejection,
                    style = MaterialTheme.typography.titleMedium,
                    color = VbColors.Coral,
                    textAlign = TextAlign.Center,
                )
                VSpace(12)
                PrimaryButton(text = "Scan again", onClick = onRetry, modifier = Modifier.fillMaxWidth())
            } else {
                Text(
                    if (forRecoverySecret) {
                        "Point your camera at the code on your recovery sheet"
                    } else {
                        "Point your camera at a Voidbind code"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    color = VbColors.TextPrimary,
                    textAlign = TextAlign.Center,
                )
                VSpace(6)
                Text(
                    if (forRecoverySecret) {
                        "It fills in the secret. Nothing is restored or checked until you confirm."
                    } else {
                        "Login requests and device invites are verified before approval."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextSecondary,
                    textAlign = TextAlign.Center,
                )
            }
            VSpace(16)
            if (!forRecoverySecret) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(14.dp))
                        .background(VbColors.Surface),
                ) {
                    ModeHint(Icons.Rounded.Public, "Web login", Modifier.weight(1f))
                    ModeHint(Icons.Rounded.Smartphone, "Pair device", Modifier.weight(1f))
                }
                VSpace(14)
            }
            OutlineButton(
                if (forRecoverySecret) "Type it instead" else "Enter code instead",
                onClick = onEnterManually,
                accent = VbColors.Mint,
                leadingIcon = Icons.Rounded.Keyboard,
            )
        }
    }
}

@Composable
private fun ModeHint(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier.padding(vertical = 14.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, contentDescription = null, tint = VbColors.Mint, modifier = Modifier.size(18.dp))
        HSpace(8)
        Text(label, style = MaterialTheme.typography.labelLarge, color = VbColors.TextPrimary)
    }
}
