package one.rarebit.voidwhichbinds.slip39

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

/**
 * Trezor's official SLIP-39 vectors (`vectors/slip39/vectors.json`, copied verbatim
 * from void-which-binds-go `testvectors/vectors/slip39/`, itself verbatim from
 * python-shamir-mnemonic, and pinned by `VOID_WHICH_BINDS_GO_REF`): every valid case
 * reproduces its master secret, and every invalid one is refused for the reason its
 * description names, exactly as void-which-binds-go's `TestTrezorVectors` requires.
 */
class Slip39VectorTest {

    /** The file's SHA-256, as void-which-binds-go pins it (testvectors/vectors/slip39/README.md). */
    private val vectorsSha256 = "13ebecebdd869dd2bc2cdf69e7ce3a158cf106cac76c39d17682b1c6cdabbdc4"

    private val raw: ByteArray = javaClass.getResourceAsStream("/vectors/slip39/vectors.json")?.readBytes()
        ?: error("no SLIP-39 vectors in test resources")

    private class Vector(val description: String, val mnemonics: List<String>, val secretHex: String)

    private val vectors: List<Vector> = run {
        // MiniJson reads objects; the file is a top-level array, so wrap it.
        val cases = MiniJson.parseObject("{\"v\":${raw.decodeToString()}}")["v"] as List<*>
        cases.map { c ->
            val fields = c as List<*>
            Vector(fields[0] as String, (fields[1] as List<*>).map { it as String }, fields[2] as String)
        }
    }

    /** The refusal each invalid case must get, keyed by a fragment of its description (Go's table). */
    private val refusals = listOf(
        "invalid checksum" to Slip39Error.CHECKSUM,
        "invalid padding" to Slip39Error.PADDING,
        "Basic sharing 2-of-3" to Slip39Error.INSUFFICIENT_SHARES,
        "different identifiers" to Slip39Error.IDENTIFIER_MISMATCH,
        "different iteration exponents" to Slip39Error.PARAMETER_MISMATCH,
        "mismatching group thresholds" to Slip39Error.PARAMETER_MISMATCH,
        "mismatching group counts" to Slip39Error.PARAMETER_MISMATCH,
        "greater group threshold than group counts" to Slip39Error.MALFORMED_SHARE,
        "duplicate member indices" to Slip39Error.DUPLICATE_INDEX,
        "mismatching member thresholds" to Slip39Error.PARAMETER_MISMATCH,
        "invalid digest" to Slip39Error.DIGEST,
        "Insufficient number of groups" to Slip39Error.INSUFFICIENT_SHARES,
        "insufficient number of members" to Slip39Error.INSUFFICIENT_SHARES,
        "insufficient length" to Slip39Error.INVALID_LENGTH,
        "invalid master secret length" to Slip39Error.INVALID_LENGTH,
    )

    @Test
    fun theVectorsArePinned() {
        val sum = Hex.encode(MessageDigest.getInstance("SHA-256").digest(raw))
        assertEquals(vectorsSha256, sum, "vectors.json changed; re-copy it from voidbind-go, never edit it")
    }

    @Test
    fun everyTrezorVectorPasses() {
        var passed = 0
        for (v in vectors) {
            if (v.secretHex.isEmpty()) {
                val want = refusals.firstOrNull { (fragment, _) -> fragment in v.description }?.second
                    ?: fail("${v.description}: no expected refusal for this case")
                val e = assertFailsWith<Slip39Exception>(v.description) { Slip39.combine(v.mnemonics, "TREZOR") }
                assertEquals(want, e.error, "${v.description}: refused with ${e.message}")
            } else {
                assertEquals(v.secretHex, Hex.encode(Slip39.combine(v.mnemonics, "TREZOR")), v.description)
            }
            passed++
        }
        assertEquals(45, vectors.size, "Trezor publishes 45 vectors")
        assertEquals(vectors.size, passed)
    }

    /** Trezor's own valid shares decode and re-encode to themselves, word for word. */
    @Test
    fun trezorSharesReencodeToThemselves() {
        for (v in vectors.filter { it.secretHex.isNotEmpty() }) {
            for (m in v.mnemonics) assertEquals(m, Share.parse(m).mnemonic(), v.description)
        }
    }
}
