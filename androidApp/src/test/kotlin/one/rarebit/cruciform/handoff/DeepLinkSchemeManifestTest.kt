package one.rarebit.cruciform.handoff

import org.junit.Assert.assertEquals
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Gen2 Cruciform registers ONE deep-link scheme filter, `void-which-binds:` only
 * (void-which-binds-go ADR-0022, restating ADR-0019): Android delivers a URI only to an
 * app whose filter declares its scheme, so the absent gen1 `voidbind` filter is what
 * keeps a gen1 link from ever reaching this app. Reads the real manifest; pure JVM.
 */
class DeepLinkSchemeManifestTest {

    private val android = "http://schemas.android.com/apk/res/android"

    /** Every `<data android:scheme>` under an activity's `<intent-filter>`s (not `<queries>`). */
    private fun activitySchemes(): List<String> {
        val manifest = listOf("src/main/AndroidManifest.xml", "androidApp/src/main/AndroidManifest.xml")
            .map(::File).firstOrNull { it.isFile }
            ?: error("AndroidManifest.xml not found from ${File(".").absolutePath}")
        val doc = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder().parse(manifest)
        val activities = doc.getElementsByTagName("activity")
        return (0 until activities.length).flatMap { a ->
            val data = (activities.item(a) as Element).getElementsByTagName("data")
            (0 until data.length).mapNotNull {
                (data.item(it) as Element).getAttributeNS(android, "scheme").ifEmpty { null }
            }
        }
    }

    @Test
    fun onlyTheGen2SchemeIsRegistered() {
        val schemes = activitySchemes()
        // `cruciform` is the same-phone pair-joined callback (ADR-0008), not a protocol scheme.
        assertEquals(listOf("void-which-binds", "cruciform"), schemes)
    }
}
