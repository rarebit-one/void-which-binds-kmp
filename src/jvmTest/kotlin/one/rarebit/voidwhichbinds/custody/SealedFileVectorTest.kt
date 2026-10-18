package one.rarebit.voidwhichbinds.custody

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.crypto.XChaCha20Poly1305
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * void-which-binds-go's custody-sealedfile vector (ADR-0021 backend 2;
 * `testvectors/vectors/custody-sealedfile/device-floor.json`, copied verbatim and pinned by
 * VOID_WHICH_BINDS_GO_REF): the Kotlin codec opens Go's blob, re-seals the same inputs to the
 * same bytes, and refuses every refusal row with the same error kind, the before-derivation
 * rows from the clear header alone (ADR-0010).
 */
class SealedFileVectorTest {

    private val v: Map<String, Any> by lazy {
        val raw = javaClass.getResourceAsStream("/vectors/custody-sealedfile/device-floor.json")
            ?.readBytes()?.decodeToString() ?: error("vectors/custody-sealedfile/device-floor.json missing")
        MiniJson.parseObject(raw)
    }

    @Suppress("UNCHECKED_CAST")
    private fun obj(m: Any?): Map<String, Any> = m as Map<String, Any>

    @Suppress("UNCHECKED_CAST")
    private fun list(m: Any?): List<Any> = m as List<Any>

    private val objects: List<SealedFile.Object> by lazy {
        list(v["objects"]).map {
            val o = obj(it)
            val kind = when (o["kind"]) {
                "x25519" -> SealedFile.Kind.X25519
                "ed25519" -> SealedFile.Kind.ED25519
                else -> error("kind ${o["kind"]}")
            }
            SealedFile.Object(kind, o["name"] as String, Hex.decode(o["seed"] as String))
        }
    }

    /** draft-irtf-cfrg-xchacha §2.2.1, also computed with Go's x/crypto chacha20.HChaCha20. */
    @Test
    fun hchacha20MatchesTheDraftVector() {
        val key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        val input = Hex.decode("000000090000004a0000000031415927")
        assertEquals(
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc",
            Hex.encode(XChaCha20Poly1305.hChaCha20(key, input)),
        )
    }

    @Test
    fun opensGosBlobAndReadsItsPublicKeysWithoutThePassphrase() {
        val f = SealedFile.parse(Hex.decode(v["blob"] as String))
        assertEquals(v["recipient_id"], f.recipientId)
        assertEquals(obj(v["signer_ids"])["device"], f.signerId("device"))
        val p = obj(v["params"])
        assertEquals(
            SealedFile.Params(p["time"] as Long, p["memory_kib"] as Long, (p["parallelism"] as Long).toInt()),
            f.params,
        )

        f.open(v["passphrase"] as String).use { opened ->
            assertContentEquals(objects[0].seed, opened.x25519Seed())
            assertContentEquals(objects[1].seed, opened.ed25519Seed("device"))
            assertEquals(null, opened.ed25519Seed("nobody"))
        }
    }

    @Test
    fun resealsTheSameInputsToTheSameBytes() {
        val p = obj(v["params"])
        val blob = SealedFile.seal(
            objects,
            (v["passphrase"] as String).encodeToByteArray(),
            SealedFile.Params(p["time"] as Long, p["memory_kib"] as Long, (p["parallelism"] as Long).toInt()),
            Hex.decode(v["salt"] as String),
            Hex.decode(v["nonce"] as String),
        )
        assertEquals(v["blob"], Hex.encode(blob))
    }

    @Test
    fun refusesEveryRefusalRowWithItsErrorKind() {
        val rows = list(v["refusals"]).map(::obj)
        assertTrue(rows.isNotEmpty())
        for (r in rows) {
            val name = r["name"] as String
            val blob = Hex.decode(r["blob"] as String)
            val want = when (r["error"]) {
                "open-failed" -> SealedFile.SealedFileException.OpenFailed::class
                "below-floor" -> SealedFile.SealedFileException.BelowFloor::class
                "above-ceiling" -> SealedFile.SealedFileException.AboveCeiling::class
                "unknown-magic" -> SealedFile.SealedFileException.UnknownMagic::class
                "unknown-kdf" -> SealedFile.SealedFileException.UnknownKdf::class
                "malformed" -> SealedFile.SealedFileException.Malformed::class
                else -> fail("$name: unknown error kind ${r["error"]}")
            }
            val got = try {
                val f = SealedFile.parse(blob)
                if (r["before_derivation"] ==
                    true
                ) {
                    fail("$name: must be refused from the clear header, before derivation")
                }
                f.open(r["passphrase"] as String).close()
                fail("$name: opened")
            } catch (e: SealedFile.SealedFileException) {
                e
            }
            assertEquals(want, got::class, "$name: $got")
        }
    }

    @Test
    fun aFreshSealRoundTripsAndRefusesAnEmptyPassphrase() {
        val pass = "a different passphrase".encodeToByteArray()
        val f = SealedFile.parse(SealedFile.seal(objects, pass))
        f.open(pass).use { assertContentEquals(objects[1].seed, it.ed25519Seed("device")) }
        assertFailsWith<SealedFile.SealedFileException.EmptyPassphrase> { f.open(ByteArray(0)) }
        assertFailsWith<SealedFile.SealedFileException.EmptyPassphrase> { SealedFile.seal(objects, ByteArray(0)) }
    }
}
