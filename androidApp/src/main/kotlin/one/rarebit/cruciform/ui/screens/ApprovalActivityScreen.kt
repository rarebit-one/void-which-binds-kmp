// Compose components are PascalCase by convention; layout spacing is literal dp.
@file:Suppress("FunctionNaming", "MagicNumber", "ktlint:standard:function-naming")

package one.rarebit.cruciform.ui.screens

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
import androidx.compose.material.icons.rounded.Cancel
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.History
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.domain.ApprovalActivity
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.HSpace
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.VSpace
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.components.VbHairline
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * The **approval activity** log: the immutable "who did I approve, and when" trail —
 * one row per approve/deny decision, newest first. Read-only; the records are appended
 * by the engine as each login is decided (see the commonMain `ApprovalAuditLog`).
 */
@Composable
fun ApprovalActivityScreen(activity: List<ApprovalActivity>, onBack: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        AppTopBar(title = "Approval activity", onBack = onBack)
        Column(Modifier.padding(ScreenPadding).padding(bottom = 28.dp)) {
            if (activity.isEmpty()) {
                EmptyState()
            } else {
                VbCard(modifier = Modifier.fillMaxWidth()) {
                    Column {
                        activity.forEachIndexed { i, entry ->
                            ActivityRow(entry)
                            if (i < activity.lastIndex) VbHairline(Modifier.padding(horizontal = 16.dp))
                        }
                    }
                }
                VSpace(14)
                Text(
                    "This log stays on your device. It records what you approved or denied — never any personal data.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextMuted,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

/** One approve/deny decision; Home shows the latest few with the same row. */
@Composable
internal fun ActivityRow(entry: ApprovalActivity) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val accent = if (entry.approved) VbColors.Mint else VbColors.Coral
        Icon(
            if (entry.approved) Icons.Rounded.CheckCircle else Icons.Rounded.Cancel,
            contentDescription = if (entry.approved) "Approved" else "Denied",
            tint = accent,
            modifier = Modifier.size(22.dp),
        )
        HSpace(14)
        Column(Modifier.weight(1f)) {
            Text(
                entry.rp,
                style = MaterialTheme.typography.titleMedium,
                color = VbColors.TextPrimary,
                fontWeight = FontWeight.Medium,
            )
            val detail = buildString {
                append(if (entry.approved) "Approved" else "Denied")
                append(" · ")
                append(entry.whenLabel)
                entry.matchNumber?.let { append(" · #$it") }
            }
            Text(detail, style = MaterialTheme.typography.bodyMedium, color = VbColors.TextSecondary)
        }
    }
}

@Composable
private fun EmptyState() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(top = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Rounded.History,
            contentDescription = null,
            tint = VbColors.TextMuted,
            modifier = Modifier.size(40.dp),
        )
        VSpace(14)
        Text("No approvals yet", style = MaterialTheme.typography.titleMedium, color = VbColors.TextSecondary)
        VSpace(6)
        Text(
            "Each sign-in you approve or deny will appear here.",
            style = MaterialTheme.typography.bodyMedium,
            color = VbColors.TextMuted,
            textAlign = TextAlign.Center,
        )
    }
}
