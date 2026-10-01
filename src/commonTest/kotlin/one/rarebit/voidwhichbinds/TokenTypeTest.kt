package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** ADR-0009 phase-1 `typ` rule, mirroring void-which-binds-go `sigtoken.CheckTyp`. */
class TokenTypeTest {
    private fun check(json: String, vararg allowed: String) = TokenType.check(MiniJson.parseObject(json), *allowed)

    @Test
    fun absentTypPassesAsLegacy() = assertEquals("", check("""{"v":2}""", TokenType.CERT))

    @Test
    fun allowedTypIsReturned() {
        assertEquals(TokenType.OP, check("""{"v":3,"typ":"voidbind.op"}""", TokenType.OP, TokenType.CERT))
    }

    @Test
    fun otherKindsAreWrongType() {
        val bodies = listOf(
            """{"typ":"voidbind.grant"}""",
            """{"typ":"Voidbind.cert"}""",
            """{"typ":""}""",
            """{"typ":"voidbind.nope"}""",
        )
        for (body in bodies) {
            val e = assertFailsWith<TokenType.TypeException> { check(body, TokenType.CERT) }
            assertEquals(TokenType.Failure.WRONG_TYPE, e.failure, body)
        }
    }

    @Test
    fun nonStringOrCaseVariantIsMalformed() {
        val bodies = listOf(
            """{"typ":7}""",
            """{"typ":null}""",
            """{"typ":{"a":1}}""",
            """{"Typ":"voidbind.cert"}""",
            """{"TYP":"x"}""",
        )
        for (body in bodies) {
            val e = assertFailsWith<TokenType.TypeException> { check(body, TokenType.CERT) }
            assertEquals(TokenType.Failure.MALFORMED, e.failure, body)
        }
    }
}
