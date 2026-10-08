package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/**
 * The space-key chain (heyarr ADR-0103, void-which-binds-go v0.26.0 `encryption/chain.go`):
 * `vectors/key-chain/three-epochs.json` is Go's `TestKeyChainVector`. Every link must
 * open with the key of its own epoch to the previous epoch's key, re-seal to the exact
 * bytes under its fixed nonce, and every refuse blob must fail with the one opaque
 * [VoidbindEncryption.UnwrapException].
 */
@Suppress("UNCHECKED_CAST")
class KeyChainVectorTest {

    private val vector: Map<String, Any?> = run {
        val raw = javaClass.getResourceAsStream("/vectors/key-chain/three-epochs.json")?.readBytes()?.decodeToString()
            ?: error("vectors/key-chain/three-epochs.json missing from test resources")
        MiniJson.parseObject(raw)
    }

    private val keys: List<ByteArray> = (vector["keys"] as List<String>).map(Hex::decode)

    @Test
    fun labelIsGos() {
        assertEquals("void-which-binds/space-key-chain/v1", vector["label"])
        assertEquals(72, VoidbindEncryption.SEALED_SPACE_KEY_SIZE)
    }

    @Test
    fun everyLinkOpensToThePreviousKeyAndReseals() {
        val links = vector["links"] as List<Map<String, Any?>>
        assertEquals(keys.size - 1, links.size, "one link per epoch after 0")
        for (link in links) {
            val epoch = (link["epoch"] as Number).toInt()
            val sealed = Hex.decode(link["sealed_prev"] as String)
            assertEquals(VoidbindEncryption.SEALED_SPACE_KEY_SIZE, sealed.size, "link $epoch length")
            val opened = VoidbindEncryption.openSpaceKey(keys[epoch], sealed)
            assertContentEquals(keys[epoch - 1], opened, "link $epoch opens")
            val nonce = Hex.decode(link["nonce"] as String)
            assertContentEquals(
                sealed,
                VoidbindEncryption.sealSpaceKeyWithNonce(keys[epoch], keys[epoch - 1], nonce),
                "link $epoch re-seals byte for byte",
            )
        }
    }

    @Test
    fun everyRefuseBlobIsTheOpaqueUnwrapError() {
        val refuse = vector["refuse"] as List<Map<String, Any?>>
        check(refuse.size >= 4) { "expected >= 4 refuse cases, found ${refuse.size}" }
        for (case in refuse) {
            val key = keys[(case["sealing_key_index"] as Number).toInt()]
            val blob = Hex.decode(case["blob"] as String)
            assertFailsWith<VoidbindEncryption.UnwrapException>(case["name"] as String) {
                VoidbindEncryption.openSpaceKey(key, blob)
            }
        }
    }

    @Test
    fun aFreshSealRoundTripsAndDrawsANewNonce() {
        val a = VoidbindEncryption.sealSpaceKey(keys[1], keys[0])
        val b = VoidbindEncryption.sealSpaceKey(keys[1], keys[0])
        assertFalse(a.contentEquals(b), "two seals of the same pair differ")
        assertContentEquals(keys[0], VoidbindEncryption.openSpaceKey(keys[1], a))
    }

    @Test
    fun aSealedKeyAndAChangeNeverOpenAsEachOther() {
        // A change whose plaintext is a 32-byte key has the same length as a sealed key.
        val change = VoidbindEncryption.encryptChange(keys[1], keys[0])
        assertEquals(VoidbindEncryption.SEALED_SPACE_KEY_SIZE, change.size)
        assertFailsWith<VoidbindEncryption.UnwrapException> { VoidbindEncryption.openSpaceKey(keys[1], change) }
        val sealed = VoidbindEncryption.sealSpaceKey(keys[1], keys[0])
        assertFailsWith<Exception> { VoidbindEncryption.decryptChange(keys[1], sealed) }
    }

    @Test
    fun aWrongSizeSealingKeyIsACallerBug() {
        assertFailsWith<IllegalArgumentException> {
            VoidbindEncryption.openSpaceKey(ByteArray(31), ByteArray(VoidbindEncryption.SEALED_SPACE_KEY_SIZE))
        }
        assertFailsWith<IllegalArgumentException> { VoidbindEncryption.sealSpaceKey(keys[0], ByteArray(16)) }
    }
}
