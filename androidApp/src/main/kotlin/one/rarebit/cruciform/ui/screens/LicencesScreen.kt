package one.rarebit.cruciform.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.R
import one.rarebit.cruciform.ui.components.AppTopBar
import one.rarebit.cruciform.ui.components.RowItem
import one.rarebit.cruciform.ui.components.ScreenPadding
import one.rarebit.cruciform.ui.components.VbCard
import one.rarebit.cruciform.ui.theme.VbColors
import org.json.JSONArray
import org.json.JSONObject

// LIC-09: ML Kit's terms make the app responsible for telling users about Google's metrics.
private const val ML_KIT_DISCLOSURE =
    "Scanning a QR code uses Google's ML Kit, which reads the camera image on " +
        "this device; the image never leaves it. ML Kit does send Google metrics about " +
        "how the scanner performs and is used (Google Privacy Policy: policies.google.com/privacy)."

/** One third-party library compiled into this app, as the AboutLibraries plugin recorded it. */
internal data class OssLibrary(
    val name: String,
    val version: String?,
    val website: String?,
    val licences: List<OssLicence>,
)

internal data class OssLicence(val name: String, val url: String?, val text: String?)

/**
 * Reads `aboutlibraries.json`, which the AboutLibraries Gradle plugin writes into
 * `res/raw` at build time from the release runtime classpath and its POMs. Libraries
 * come back sorted by name; a licence id the file does not define is kept as its id,
 * so nothing listed is silently dropped.
 */
internal fun parseOssLibraries(json: String): List<OssLibrary> {
    val root = JSONObject(json)
    val licences = root.optJSONObject("licenses") ?: JSONObject()
    val libraries = root.optJSONArray("libraries") ?: JSONArray()
    return (0 until libraries.length()).map { i ->
        val lib = libraries.getJSONObject(i)
        val ids = lib.optJSONArray("licenses") ?: JSONArray()
        OssLibrary(
            name = lib.optString("name").ifBlank { lib.optString("uniqueId") },
            version = lib.optString("artifactVersion").ifBlank { null },
            website = lib.optString("website").ifBlank { null },
            licences = (0 until ids.length()).map { j ->
                val id = ids.getString(j)
                val def = licences.optJSONObject(id)
                OssLicence(
                    name = def?.optString("name")?.ifBlank { null } ?: id,
                    url = def?.optString("url")?.ifBlank { null },
                    text = def?.optString("content")?.ifBlank { null },
                )
            },
        )
    }.sortedBy { it.name.lowercase() }
}

/** Manage → Open-source licences: every third-party library in this build and its licence. */
@Suppress("FunctionNaming", "ktlint:standard:function-naming") // Composables are PascalCase by Compose convention.
@Composable
fun LicencesScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val libraries = remember {
        context.resources.openRawResource(R.raw.aboutlibraries).bufferedReader().use {
            parseOssLibraries(it.readText())
        }
    }
    var expanded by rememberSaveable { mutableStateOf<String?>(null) }

    Column(modifier.fillMaxSize()) {
        AppTopBar(title = "Open-source licences", onBack = onBack)
        LazyColumn(Modifier.padding(ScreenPadding)) {
            item {
                Text(
                    "Cruciform is built with these open-source libraries. Tap one to read its licence.\n\n" +
                        ML_KIT_DISCLOSURE,
                    style = MaterialTheme.typography.bodyMedium,
                    color = VbColors.TextMuted,
                    modifier = Modifier.padding(bottom = 16.dp),
                )
            }
            items(libraries, key = { it.name + "@" + it.version }) { lib ->
                val key = lib.name + "@" + lib.version
                VbCard(modifier = Modifier.fillMaxWidth().padding(bottom = 10.dp)) {
                    Column {
                        RowItem(
                            title = lib.name,
                            subtitle = listOfNotNull(
                                lib.version,
                                lib.licences.joinToString { it.name }.ifBlank { null },
                            ).joinToString(" · "),
                            onClick = { expanded = if (expanded == key) null else key },
                        )
                        if (expanded == key) {
                            Column(Modifier.padding(horizontal = 16.dp).padding(bottom = 14.dp)) {
                                lib.website?.let {
                                    Text(it, style = MaterialTheme.typography.bodySmall, color = VbColors.TextMuted)
                                }
                                lib.licences.forEach { licence ->
                                    Text(
                                        licence.text ?: licence.url ?: licence.name,
                                        style = MaterialTheme.typography.bodySmall
                                            .copy(fontFamily = FontFamily.Monospace),
                                        color = VbColors.TextPrimary,
                                        modifier = Modifier.padding(top = 8.dp),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
