package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * void-which-binds-go's custody-signer vector (ADR-0021,
 * `testvectors/vectors/custody-signer/counting-seed.json`, copied verbatim and pinned
 * by `VOID_WHICH_BINDS_GO_REF`): from the counting seed `00..1f`, this library's
 * software Ed25519 must derive the same `signer_id` and mint the same
 * `base64url(body) "." base64url(signature)` token byte for byte as every Go custody
 * signer. (The `custody-sealedfile/` vector is Go-side only; it is not replayed here.)
 */
class CustodySignerVectorTest {

    @Test
    fun countingSeedMintsGosToken() {
        val raw = javaClass.getResourceAsStream("/vectors/custody-signer/counting-seed.json")
            ?.readBytes()?.decodeToString() ?: error("vectors/custody-signer/counting-seed.json missing")
        val v = MiniJson.parseObject(raw)
        assertEquals("counting-seed", v["name"])

        val seed = Hex.decode(v["seed"] as String)
        val body = Hex.decode(v["body"] as String)
        val publicKey = Ed25519Group.publicKeyFromSeed(seed)
        assertEquals(v["signer_id"], KeyRef.ed25519(publicKey).render(), "signer_id")

        val signature = Ed25519Engine.sign(seed, body)
        assertTrue(Ed25519Engine.verify(publicKey, body, signature), "signature must verify")
        val token = "${Base64Url.encode(body)}.${Base64Url.encode(signature)}"
        assertEquals(v["token"], token, "token")
    }
}
