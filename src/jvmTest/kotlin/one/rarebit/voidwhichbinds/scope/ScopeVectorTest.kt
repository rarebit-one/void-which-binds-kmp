package one.rarebit.voidwhichbinds.scope

import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * void-which-binds-go's scope vectors (`testvectors/vectors/scope/`, copied verbatim):
 * `valid.json`, `refusals.json` and `lists.json` replayed against [Scope]. The broker's
 * `intersect.json` is server-side and not replayed.
 */
@Suppress("UNCHECKED_CAST")
class ScopeVectorTest {
    private fun load(name: String): Map<String, Any> = MiniJson.parseObject(
        javaClass.getResourceAsStream("/vectors/scope/$name.json")!!.readBytes().decodeToString(),
    )

    @Test
    fun validScopesValidate() {
        val scopes = load("valid")["scopes"] as List<String>
        assertTrue(scopes.isNotEmpty())
        for (s in scopes) {
            Scope.validate(s)
            assertEquals(listOf(s), Scope.canonicalList(listOf(s)), s)
        }
    }

    @Test
    fun refusalsAreMalformed() {
        val cases = load("refusals")["cases"] as List<Map<String, Any>>
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            assertEquals("malformed", c["expect"])
            val s = c["scope"] as String
            assertFalse(Scope.isValid(s), "${c["why"]}: \"$s\"")
            assertFailsWith<ScopeException>("${c["why"]}") { Scope.canonicalList(listOf(s)) }
        }
    }

    @Test
    fun listsCanonicaliseAtMintAndAreRefusedAtVerify() {
        val cases = load("lists")["cases"] as List<Map<String, Any>>
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            val why = c["why"] as String
            val input = c["input"] as List<String>
            val canonical = c["canonical"] as? List<String> // a JSON null: the minter refuses
            val minted = runCatching { Scope.canonicalList(input) }.getOrNull()
            assertEquals(canonical, minted, "$why: canonical")
            val verify = if (runCatching { Scope.validateList(input) }.isSuccess) "ok" else "malformed"
            assertEquals(c["verify"], verify, "$why: verify")
        }
    }
}
