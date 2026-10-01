package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** The typed-only `typ` rule (ADR-0009, ADR-0022), mirroring void-which-binds-go `sigtoken.CheckTyp`. */
class TokenTypeTest {
    private fun check(json: String, vararg allowed: String) = TokenType.check(MiniJson.parseObject(json), *allowed)

    @Test
    fun absentTypIsWrongType() {
        // Gen2 is typed-only: an untyped (gen1) body is refused like a foreign kind.
        val e = assertFailsWith<TokenType.TypeException> { check("""{"v":2}""", TokenType.CERT) }
        assertEquals(TokenType.Failure.WRONG_TYPE, e.failure)
    }

    @Test
    fun allowedTypIsReturned() {
        assertEquals(TokenType.OP, check("""{"v":3,"typ":"void-which-binds.op"}""", TokenType.OP, TokenType.CERT))
    }

    @Test
    fun otherKindsAreWrongType() {
        val bodies = listOf(
            """{"typ":"void-which-binds.grant"}""",
            """{"typ":"Void-Which-Binds.cert"}""",
            """{"typ":""}""",
            """{"typ":"void-which-binds.nope"}""",
            """{"typ":"void-which-binds.roster"}""",
            // the gen1 values are simply foreign (ADR-0022)
            """{"typ":"voidbind.cert"}""",
            """{"typ":"voidbind.op"}""",
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
            """{"Typ":"void-which-binds.cert"}""",
            """{"TYP":"x"}""",
        )
        for (body in bodies) {
            val e = assertFailsWith<TokenType.TypeException> { check(body, TokenType.CERT) }
            assertEquals(TokenType.Failure.MALFORMED, e.failure, body)
        }
    }
}
