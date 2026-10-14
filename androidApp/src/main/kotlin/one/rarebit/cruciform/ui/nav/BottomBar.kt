// Compose components are PascalCase by convention; layout spacing is literal dp.
@file:Suppress("FunctionNaming", "MagicNumber", "ktlint:standard:function-naming")

package one.rarebit.cruciform.ui.nav

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * The three-slot bottom bar: Home (the everyday view), a centered Scan action, and Manage
 * (the identity, devices, sites, recovery and connections Home keeps out of the way).
 */
@Composable
fun CruciformBottomBar(currentRoute: String?, onHome: () -> Unit, onScan: () -> Unit, onManage: () -> Unit) {
    // Android 15 draws edge to edge at targetSdk 35: without the inset, the gesture
    // handle sits over the Scan label.
    Surface(color = VbColors.Background) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceAround,
        ) {
            BarItem(Icons.Rounded.Home, "Home", selected = currentRoute == Routes.HOME, onClick = onHome)
            ScanButton(onScan)
            BarItem(Icons.Rounded.Tune, "Manage", selected = currentRoute == Routes.MANAGE, onClick = onManage)
        }
    }
}

@Composable
private fun BarItem(icon: ImageVector, label: String, selected: Boolean, onClick: () -> Unit) {
    val tint = if (selected) VbColors.Mint else VbColors.TextMuted
    Column(
        modifier = Modifier
            .clip(RoundedCornerShape(16.dp))
            .clickable(onClick = onClick)
            .background(if (selected) VbColors.MintWash else VbColors.Background)
            .padding(horizontal = 22.dp, vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(icon, contentDescription = label, tint = tint, modifier = Modifier.size(26.dp))
        Text(
            label,
            style = androidx.compose.material3.MaterialTheme.typography.labelMedium,
            color = tint,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ScanButton(onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            modifier = Modifier
                .size(52.dp)
                .clip(RoundedCornerShape(17.dp))
                .border(BorderStroke(1.dp, VbColors.Mint.copy(alpha = 0.48f)), RoundedCornerShape(17.dp))
                .background(VbColors.Mint)
                .clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Rounded.QrCodeScanner,
                contentDescription = "Scan",
                tint = VbColors.OnMint,
                modifier = Modifier.size(25.dp),
            )
        }
        Text("Scan", style = androidx.compose.material3.MaterialTheme.typography.labelMedium, color = VbColors.Mint)
    }
}
