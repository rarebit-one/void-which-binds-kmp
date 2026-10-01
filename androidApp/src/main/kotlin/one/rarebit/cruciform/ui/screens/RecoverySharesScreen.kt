package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Groups
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.PrimaryButton
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.SecureScreen
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.WashCard
import one.rarebit.cruciform.ui.theme.VbColors
import one.rarebit.cruciform.ui.theme.VbType
import one.rarebit.voidwhichbinds.RecoveryShares

/**
 * Recovery shares (void-which-binds-go ADR-0011): the kept recovery secret split into SLIP-39
 * [shares] (never empty), any [threshold] of which restore the identity, shown one at
 * a time for the person to write down and hand out.
 *
 * Screenshots are blocked, as on the recovery backup screen, and there is no copy
 * action: a share is secret material and never passes through the clipboard. The
 * shares are held in memory only while this screen is up; leaving it forgets them.
 */
@Composable
fun RecoverySharesScreen(
    shares: List<String>,
    onBack: () -> Unit,
    onDone: () -> Unit,
    modifier: Modifier = Modifier,
    threshold: Int = RecoveryShares.DEFAULT_THRESHOLD,
) {
    SecureScreen()
    // Which share is up. Only a position, not a secret, so it may survive a rotation.
    var index by rememberSaveable { mutableIntStateOf(0) }
    val current = index.coerceIn(0, shares.lastIndex)
    val last = current == shares.lastIndex

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        AppTopBar(title = "Recovery shares", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 24.dp)) {
            Text("WRITE DOWN EACH SHARE", style = VbType.SectionLabel, color = VbColors.Amber)

            VSpace(16)
            VbCard(
                modifier = Modifier.fillMaxWidth(),
                border = BorderStroke(1.dp, VbColors.Mint.copy(alpha = 0.5f)),
            ) {
                Column(Modifier.padding(18.dp)) {
                    Text(
                        "Share ${current + 1} of ${shares.size} · any $threshold restore your identity",
                        style = MaterialTheme.typography.titleMedium,
                        color = VbColors.Mint,
                        fontWeight = FontWeight.SemiBold,
                    )
                    VSpace(12)
                    ShareWords(shares[current])
                }
            }

            VSpace(16)
            SharesNote(threshold)

            VSpace(20)
            PrimaryButton(
                text = if (last) "Done" else "Next",
                onClick = {
                    if (last) {
                        onDone()
                    } else {
                        index = current + 1
                    }
                },
                fill = VbColors.Mint,
                modifier = Modifier.fillMaxWidth(),
            )
            VSpace(16)
            Text(
                "Screenshots disabled on this screen",
                style = MaterialTheme.typography.bodyMedium,
                color = VbColors.TextMuted,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/**
 * A share's words, numbered, in two columns read top to bottom (1–17, then 18–33).
 * Monospace keeps the numbers and words aligned.
 */
@Composable
private fun ShareWords(share: String) {
    val words = share.trim().split(Regex("\\s+"))
    val perColumn = ((words.size + 1) / 2).coerceAtLeast(1)
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
        words.withIndex().chunked(perColumn).forEach { column ->
            Column(Modifier.weight(1f)) {
                column.forEach { (i, word) ->
                    Text(
                        "${(i + 1).toString().padStart(2)}  $word",
                        style = VbType.Mono,
                        color = VbColors.TextPrimary,
                        modifier = Modifier.padding(vertical = 3.dp),
                    )
                }
            }
        }
    }
}

/** Where the shares go, what one alone reveals, and that the written secret still works. */
@Composable
private fun SharesNote(threshold: Int) {
    WashCard(accent = VbColors.Amber, wash = VbColors.AmberWash, modifier = Modifier.fillMaxWidth()) {
        Row {
            Icon(
                Icons.Rounded.Groups,
                contentDescription = null,
                tint = VbColors.Amber,
                modifier = Modifier.size(28.dp),
            )
            HSpace(12)
            Column {
                Text(
                    "Give each share to a different person or place.",
                    style = MaterialTheme.typography.titleMedium,
                    color = VbColors.Amber,
                    fontWeight = FontWeight.SemiBold,
                )
                VSpace(6)
                Text(
                    "A share alone reveals nothing; any $threshold together restore your identity. " +
                        "Splitting doesn't revoke your written recovery secret: it still works on its " +
                        "own, so keep it safe too. Each split makes a new set, and shares from " +
                        "different splits don't combine.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextSecondary,
                )
            }
        }
    }
}
