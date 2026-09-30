package one.rarebit.voidbind

import one.rarebit.voidbind.crypto.Ed25519Group
import one.rarebit.voidbind.crypto.Hex
import one.rarebit.voidbind.crypto.MiniJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Re-MINTS every co-signed op in voidbind-go's golden membership vectors
 * (`vectors/membership/`, pinned by `VOIDBIND_GO_REF`) with this library's
 * [MembershipOp.cosign] and [MembershipOp.attachCosigs], from the vector's own
 * test-only seeds, and asserts the result is Go's token byte-for-byte.
 *
 * Go minted each one as `signOp` → `VerifyOp` → `CosignOp` per cosigner →
 * `AttachCosigs(primary, …)` (enrolment/membership_test.go `cosignedRemove`). So
 * stripping the cosigs off the parsed op recovers the proposal the cosigners
 * signed; each cosig re-made from its signer's seed must equal the vector's, and
 * re-attaching them under the primary must reproduce the vector's token (and hash).
 * JDK Ed25519 is deterministic, so this is exact equality.
 */
class CosignVectorTest {

    @Suppress("UNCHECKED_CAST")
    @Test
    fun everyGoldenCosignedOpReMintsByteForByte() {
        val dir = javaClass.getResource("/vectors/membership") ?: error("vectors/membership missing")
        val files = File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty().sorted()
        var cosignedOps = 0
        var cosigs = 0
        for (file in files) {
            val o = MiniJson.parseObject(file.readText())
            val keys = (o["keys"] as? Map<String, Map<String, Any>>).orEmpty()
            // rendered ed25519 id -> signing seed
            val seedById = keys.values.mapNotNull { k ->
                val seed = (k["sign_seed"] as? String)?.let(Hex::decode) ?: return@mapNotNull null
                KeyRef.ed25519(Ed25519Group.publicKeyFromSeed(seed)).render() to seed
            }.toMap()
            for (entry in o["ops"] as List<Map<String, Any>>) {
                val n = reMint(file.name, entry, seedById) ?: continue
                cosignedOps++
                cosigs += n
            }
        }
        // cosig-threshold-met, cosig-nonmember-ignored, cosig-reserved and
        // typed-cosig-threshold-met carry cosigs today; guard against a vacuous pass.
        assertTrue(
            cosignedOps >= MIN_COSIGNED_OPS,
            "expected >= $MIN_COSIGNED_OPS cosigned vector ops, found $cosignedOps",
        )
        println("cosign vector parity: $cosignedOps cosigned ops, $cosigs cosigs re-minted")
    }

    /**
     * Re-mint one vector op if it carries cosigs; returns how many cosigs were re-made
     * (0 when all were hand-injected), or null when there is nothing to re-mint.
     */
    private fun reMint(fileName: String, entry: Map<String, Any>, seedById: Map<String, ByteArray>): Int? {
        val token = entry["token"] as String
        // A junk / malformed vector op, or one with no cosigs: nothing to re-mint.
        val op = runCatching { MembershipOp.verify(token) }.getOrNull()?.takeIf { it.cosig.isNotEmpty() }
            ?: return null
        val where = "$fileName ${entry["label"]}"
        val proposal = op.copy(cosig = emptyList())
        val msg = MembershipOp.cosigMessage(MembershipOp.coreBytes(proposal))
        var remadeCount = 0
        val remade = op.cosig.map { cs ->
            // A deliberately invalid cosig (cosig-reserved's `AAAA`) was injected by
            // hand, not minted by CosignOp: attach it verbatim, re-mint only real ones.
            val sig = MembershipOp.decodeSigOrNull(cs.sig)
            val pubKey = KeyRef.parse(cs.by).bytes
            val valid = sig != null && runCatching { Ed25519Engine.verify(pubKey, msg, sig) }.getOrDefault(false)
            if (!valid) return@map cs
            val seed = assertNotNull(seedById[cs.by], "$where: no seed for cosigner ${cs.by}")
            val mine = MembershipOp.cosign({
                Ed25519Engine.sign(seed, it)
            }, Ed25519Group.publicKeyFromSeed(seed), proposal)
            assertEquals(cs, mine, "$where: cosig by ${cs.by} must equal voidbind-go CosignOp")
            remadeCount++
            mine
        }
        val primarySeed = assertNotNull(seedById[op.by], "$where: no seed for primary ${op.by}")
        val reminted = MembershipOp.attachCosigs(
            { Ed25519Engine.sign(primarySeed, it) },
            Ed25519Group.publicKeyFromSeed(primarySeed),
            proposal,
            remade,
        )
        assertEquals(token, reminted, "$where: attachCosigs must reproduce voidbind-go AttachCosigs")
        assertEquals(entry["hash"], MembershipOp.hash(reminted), "$where: hash")
        return remadeCount
    }

    private companion object {
        const val MIN_COSIGNED_OPS = 4
    }
}
