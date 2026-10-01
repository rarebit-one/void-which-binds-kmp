package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The pairing-refusal vector of void-which-binds-go ADR-0012
 * (`testvectors/vectors/pair-refusal-vector.json`, copied verbatim): [PairRefusal]
 * must mint the honest refusal byte for byte, and reach Go's `refused` / `ignored`
 * verdict for every token (third-party signer, `by` that is not the signer, another
 * session, untyped, wrong or wrong-case `typ`, unknown `v`, bad signature).
 */
class PairRefusalVectorTest {

    @Suppress("UNCHECKED_CAST")
    private val vector: Map<String, Any> = run {
        val raw = javaClass.getResourceAsStream("/vectors/pair-refusal-vector.json")?.readBytes()?.decodeToString()
            ?: error("vectors/pair-refusal-vector.json missing")
        MiniJson.parseObject(raw)
    }

    @Suppress("UNCHECKED_CAST")
    private fun section(name: String): Map<String, Any> = vector[name] as Map<String, Any>

    @Suppress("UNCHECKED_CAST")
    private fun key(label: String): Map<String, Any> = section("keys")[label] as Map<String, Any>

    private fun salt(label: String): ByteArray = Hex.decode(section("salts")[label] as String)

    @Test
    fun constantsMatchGo() {
        assertEquals(PairRefusal.TYP, vector["typ"])
        assertEquals(PairRefusal.SESSION_LABEL, vector["session_label"])
        for ((label, ses) in section("ses")) {
            assertEquals(ses, PairRefusal.session(salt(label)), "ses of $label")
        }
    }

    @Test
    fun mintsTheHonestRefusalByteForByte() {
        val seed = Hex.decode(key("initiator")["sign_seed"] as String)
        val pub = Ed25519Group.publicKeyFromSeed(seed)
        assertEquals(key("initiator")["id"], KeyRef.ed25519(pub).render())

        val token = PairRefusal.sign({ Ed25519Engine.sign(seed, it) }, pub, salt("session"))
        val body = Base64Url.decode(token.substringBefore('.')).decodeToString()
        assertEquals(section("bodies")["refusal"], body, "the refusal body")
        assertEquals(section("tokens")["refusal"], token, "Ed25519 is deterministic on the JVM")
        assertTrue(PairRefusal.verify(token, pub, salt("session")))
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun replaysEveryVerdict() {
        val checks = vector["checks"] as List<Map<String, Any>>
        assertTrue(checks.size >= 10, "expected the full check list, found ${checks.size}")
        for (c in checks) {
            val token = section("tokens")[c["token"] as String] as String
            val initiator = KeyRef.parse(key(c["initiator"] as String)["id"] as String).bytes
            val got = if (PairRefusal.verify(token, initiator, salt(c["salt"] as String))) "refused" else "ignored"
            assertEquals(c["expect"], got, "${c["token"]} against ${c["initiator"]}/${c["salt"]}")
        }
    }
}
