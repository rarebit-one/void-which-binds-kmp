package one.rarebit.cruciform.ui.screens

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class OssLibrariesTest {
    private val json = """
        {
          "libraries": [
            {"uniqueId": "com.squareup.okhttp3:okhttp", "name": "OkHttp", "artifactVersion": "4.12.0",
             "website": "https://square.github.io/okhttp/", "licenses": ["Apache-2.0"]},
            {"uniqueId": "com.example:bare", "artifactVersion": "", "licenses": ["Custom-1"]},
            {"uniqueId": "androidx.core:core", "name": "Core", "artifactVersion": "1.13.1", "licenses": []}
          ],
          "licenses": {
            "Apache-2.0": {"name": "Apache License 2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0",
                           "content": "Apache License\nVersion 2.0, January 2004"}
          }
        }
    """.trimIndent()

    @Test
    fun `sorts by name and resolves licence texts`() {
        val libs = parseOssLibraries(json)
        assertEquals(listOf("com.example:bare", "Core", "OkHttp"), libs.map { it.name })
        val okhttp = libs.last()
        assertEquals("4.12.0", okhttp.version)
        assertEquals("Apache License 2.0", okhttp.licences.single().name)
        assertEquals("Apache License\nVersion 2.0, January 2004", okhttp.licences.single().text)
    }

    @Test
    fun `keeps a licence id the file does not define rather than dropping it`() {
        val bare = parseOssLibraries(json).first()
        assertNull(bare.version)
        assertEquals("Custom-1", bare.licences.single().name)
        assertNull(bare.licences.single().text)
    }
}
