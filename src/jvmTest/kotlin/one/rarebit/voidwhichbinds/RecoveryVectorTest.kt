package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * void-which-binds-go's recovery known answers (`testvectors/vectors/recovery/`, ADR-0010),
 * copied verbatim and pinned by `VOID_WHICH_BINDS_GO_REF`: for fixed entropy, the bech32m
 * secret in both cases, the user identity and the printable fingerprint must match
 * Go byte-for-byte. (The recovery encryption key is not derived by this library yet.)
 */
class RecoveryVectorTest {

    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/recovery") ?: error("no recovery vectors in test resources")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }!!
            .map { it.name.removeSuffix(".json") }
            .sorted()
    }

    @Test
    fun everyRecoveryVectorMatchesGo() {
        assertTrue(cases.size >= 3, "expected the recovery vectors, found $cases")
        for (name in cases) {
            val raw = javaClass.getResourceAsStream("/vectors/recovery/$name.json")!!.readBytes().decodeToString()
            val v = MiniJson.parseObject(raw)
            assertEquals(name, v["name"], "vector file stem must equal its name")
            val entropy = Hex.decode(v["entropy"] as String)
            val secret = RecoverySecret.of(entropy)

            assertEquals(v["secret"], secret.format(), "$name: bech32m rendering")
            assertContentEquals(entropy, RecoverySecret.parse(v["secret_upper"] as String).bytes, "$name: the QR form")
            val user = UserIdentity.fromSecret(secret)
            assertEquals(v["user_id"], user.userId.render(), "$name: user identity")
            assertEquals(v["fingerprint"], user.fingerprint, "$name: fingerprint")
        }
    }

    @Test
    fun aKeyOfTheWrongLengthHasNoFingerprint() {
        assertEquals("", UserFingerprint.of(ByteArray(31)))
    }
}
