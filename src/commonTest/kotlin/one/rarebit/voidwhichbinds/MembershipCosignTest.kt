package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The ADR-0008 co-signing PRIMITIVES — [MembershipOp.cosign] and
 * [MembershipOp.attachCosigs], ports of void-which-binds-go `enrolment.CosignOp` and
 * `enrolment.AttachCosigs`. Two halves:
 *
 *  - **Byte parity** with void-which-binds-go's `TestSignGolden` (`enrolment/golden_test.go`,
 *    void-which-binds-go v0.19.0): from the same fixed keys (`goldenKey(base)` — seed byte i
 *    is `base + i`) the uncosigned remove, its cosig and the re-minted cosigned token
 *    must equal Go's (gen2: typed-only, ADR-0022; the gen1 goldens are refused). On a
 *    randomized-Ed25519 target (iOS) the signatures are checked by verification and
 *    the payloads byte-for-byte (see [assertMatchesGoToken]).
 *  - **Round trip** through [Membership.evaluate]: at fleet high-water 3 (k = 2) a
 *    member's lone remove is `under_threshold`, and the SAME remove co-signed here by
 *    a second member takes effect — the flow Cruciform's removeDevice needs.
 *
 * The golden membership vectors' cosigned removes are re-minted from their seeds by
 * `CosignVectorTest` (jvmTest, which reads the vector resources).
 */
class MembershipCosignTest {

    private fun goldenSeed(base: Int) = ByteArray(32) { (base + it).toByte() }
    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private fun pub(seed: ByteArray) = Ed25519Group.publicKeyFromSeed(seed)

    private val userSeed = goldenSeed(0x10)
    private val cosignerSeed = goldenSeed(0x70)

    // void-which-binds-go enrolment/golden_test.go TestSignGolden (gen2, ADR-0022): {"op"|"cosig"|"cosigned op", want}.
    @Suppress("MaxLineLength")
    private val goOp =
        "eyJ2IjozLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLm9wIiwidXNyIjoiZWQyNTUxOTo3Nzc2ZTg3MGI5MzM1NGYyYTBiMjRjMjNmMmEzNmNjNGU4MGUyMjMyMThjMWI5NzkyNmZkZDAxODM5NmEyYjliIiwib3AiOiJyZW1vdmUiLCJkZXYiOiJlZDI1NTE5OjI1NDNiOTJmZjEwOTU1MTE0NzZhZGM4MzY5ZGI2ZGRjOTMzNjY1YTExOTc4ZGRhMTQwNGVlMTA2NmNhOTU1OWQiLCJieSI6ImVkMjU1MTk6Nzc3NmU4NzBiOTMzNTRmMmEwYjI0YzIzZjJhMzZjYzRlODBlMjIzMjE4YzFiOTc5MjZmZGQwMTgzOTZhMmI5YiIsInByZXYiOltdLCJpYXQiOjE3ODc3NDU2MDB9.h4XmD0wUfC7hrRAXqvhGNWKX99dhXeRYzJ-OD2BwFaEbWmjOIR7bTOTujr2BldTrwQZDA-N0HTEqjZHJPAWiAg"
    private val goCosig = "tPysFgSzfIc0DmGwVnBrIs7see9-soOOLwwtEjfJOLvzkdQAY5hZMt1a-risceIWPftcx5B1srs8E_gU78t-Bw"

    @Suppress("MaxLineLength")
    private val goCosigned =
        "eyJ2IjozLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLm9wIiwidXNyIjoiZWQyNTUxOTo3Nzc2ZTg3MGI5MzM1NGYyYTBiMjRjMjNmMmEzNmNjNGU4MGUyMjMyMThjMWI5NzkyNmZkZDAxODM5NmEyYjliIiwib3AiOiJyZW1vdmUiLCJkZXYiOiJlZDI1NTE5OjI1NDNiOTJmZjEwOTU1MTE0NzZhZGM4MzY5ZGI2ZGRjOTMzNjY1YTExOTc4ZGRhMTQwNGVlMTA2NmNhOTU1OWQiLCJieSI6ImVkMjU1MTk6Nzc3NmU4NzBiOTMzNTRmMmEwYjI0YzIzZjJhMzZjYzRlODBlMjIzMjE4YzFiOTc5MjZmZGQwMTgzOTZhMmI5YiIsInByZXYiOltdLCJjb3NpZyI6W3siYnkiOiJlZDI1NTE5OjFjZTU2YTQ4YzgyZmY5OTE2MmExNGJjNTQ0NjEyNjc0ZTVkNjFmYjkzMTdlNjVkNDA1NTc4MGZkYmNiNGRjMzUiLCJzaWciOiJ0UHlzRmdTemZJYzBEbUd3Vm5CcklzN3NlZTktc29PT0x3d3RFamZKT0x2emtkUUFZNWhaTXQxYS1yaXNjZUlXUGZ0Y3g1QjFzcnM4RV9nVTc4dC1CdyJ9XSwiaWF0IjoxNzg3NzQ1NjAwfQ.8bIfoPVaIFnRBWhiguNI-wB0a7HNiu4dWBmvPcr_u0MEZUiJGLAeA5Vmm__FtZuo20zop6whO-O1LbFr1CSEDw"

    // The gen1 goldens of the same inputs (TestSignGolden's legacyGoldenOp and
    // gen1TypedGoldenOp), kept only as refusal inputs: gen2 is typed-only.
    @Suppress("MaxLineLength")
    private val gen1UntypedOp =
        "eyJ2IjozLCJ1c3IiOiJlZDI1NTE5Ojc3NzZlODcwYjkzMzU0ZjJhMGIyNGMyM2YyYTM2Y2M0ZTgwZTIyMzIxOGMxYjk3OTI2ZmRkMDE4Mzk2YTJiOWIiLCJvcCI6InJlbW92ZSIsImRldiI6ImVkMjU1MTk6MjU0M2I5MmZmMTA5NTUxMTQ3NmFkYzgzNjlkYjZkZGM5MzM2NjVhMTE5NzhkZGExNDA0ZWUxMDY2Y2E5NTU5ZCIsImJ5IjoiZWQyNTUxOTo3Nzc2ZTg3MGI5MzM1NGYyYTBiMjRjMjNmMmEzNmNjNGU4MGUyMjMyMThjMWI5NzkyNmZkZDAxODM5NmEyYjliIiwicHJldiI6W10sImlhdCI6MTc4Nzc0NTYwMH0.JJDohlpMnU5yd1Stg5ghuXr5aJfprr9gugHFnRyqbe0lFb8baOvN7B0y0-5a5SXmVB0vW0iieVsE7_SQo1nJAg"

    @Suppress("MaxLineLength")
    private val gen1TypedOp =
        "eyJ2IjozLCJ0eXAiOiJ2b2lkYmluZC5vcCIsInVzciI6ImVkMjU1MTk6Nzc3NmU4NzBiOTMzNTRmMmEwYjI0YzIzZjJhMzZjYzRlODBlMjIzMjE4YzFiOTc5MjZmZGQwMTgzOTZhMmI5YiIsIm9wIjoicmVtb3ZlIiwiZGV2IjoiZWQyNTUxOToyNTQzYjkyZmYxMDk1NTExNDc2YWRjODM2OWRiNmRkYzkzMzY2NWExMTk3OGRkYTE0MDRlZTEwNjZjYTk1NTlkIiwiYnkiOiJlZDI1NTE5Ojc3NzZlODcwYjkzMzU0ZjJhMGIyNGMyM2YyYTM2Y2M0ZTgwZTIyMzIxOGMxYjk3OTI2ZmRkMDE4Mzk2YTJiOWIiLCJwcmV2IjpbXSwiaWF0IjoxNzg3NzQ1NjAwfQ._O8n_H1derB9rfHskQdYaD7bc2DOAxk40gCzdq7VFhC8nllY4cFO_V2p-lOaeIsXf63RE2NMQvhPJY85t8bSAw"

    private fun assertGoldenCosignFlow(opToken: String, wantSig: String, wantCosigned: String, label: String) {
        val op = MembershipOp.verify(opToken)
        val cs = MembershipOp.cosign(signer(cosignerSeed), pub(cosignerSeed), op)
        assertEquals(KeyRef.ed25519(pub(cosignerSeed)).render(), cs.by, "$label: cosig by is the cosigner's key")
        assertMatchesGoSignature(
            wantSig,
            cs.sig,
            pub(cosignerSeed),
            MembershipOp.cosigMessage(MembershipOp.coreBytes(op)),
            "$label: cosig must equal void-which-binds-go CosignOp",
        )
        // Attach Go's own cosig so the payload is deterministic on every target; the
        // re-minted token must then be Go's AttachCosigs output.
        val goCosig = cs.copy(sig = wantSig)
        val cosigned = MembershipOp.attachCosigs(signer(userSeed), pub(userSeed), op, listOf(goCosig))
        assertMatchesGoToken(
            wantCosigned,
            cosigned,
            pub(userSeed),
            "$label: cosigned op must equal void-which-binds-go AttachCosigs",
        )
        val back = MembershipOp.verify(cosigned)
        assertEquals(op.typ, back.typ, "$label: attachCosigs keeps the op's typ")
        assertEquals(listOf(goCosig), back.cosig)
        assertTrue(
            Hex.encode(MembershipOp.coreBytes(op)) == Hex.encode(MembershipOp.coreBytes(back)),
            "$label: the core is invariant under attaching cosigs",
        )
    }

    @Test
    fun cosignFlowReproducesGoGoldenByteForByte() = assertGoldenCosignFlow(goOp, goCosig, goCosigned, "gen2")

    @Test
    fun gen1GoldensAreRefusedAsWrongType() {
        // Mirrors void-which-binds-go TestGen1GoldensAreRefused (ADR-0022).
        for (tok in listOf(gen1UntypedOp, gen1TypedOp)) {
            val e = assertFailsWith<MembershipOp.OpException> { MembershipOp.verify(tok) }
            assertEquals(MembershipOp.Failure.WRONG_TYPE, e.failure)
        }
    }

    @Test
    fun attachCosigsRefusesAPrimaryThatIsNotBy() {
        val op = MembershipOp.verify(goOp)
        val cs = MembershipOp.cosign(signer(cosignerSeed), pub(cosignerSeed), op)
        val e = assertFailsWith<MembershipOp.OpException> {
            MembershipOp.attachCosigs(signer(cosignerSeed), pub(cosignerSeed), op, listOf(cs))
        }
        assertEquals(MembershipOp.Failure.MALFORMED, e.failure)
    }

    @Test
    fun attachingNoCosigsReproducesTheBarePayload() {
        val op = MembershipOp.verify(goOp)
        val bare = MembershipOp.attachCosigs(signer(userSeed), pub(userSeed), op, emptyList())
        assertEquals(goOp.substringBefore('.'), bare.substringBefore('.'), "empty cosigs are omitted (omitempty)")
        assertEquals(Base64Url.encode(MembershipOp.coreBytes(op)), bare.substringBefore('.'))
    }

    // --- round trip through Membership.evaluate (ADR-0008 rule 5) -------------------

    // Fixed test-only keys (the pre-gen2 cosig-threshold-met vector's; any keys do).
    private val genesisSeed = Hex.decode("c24bb87672097fd3292251030126197ba061ffb69b9b67b0786318f627fb132c")
    private val aSeed = Hex.decode("5a855e9adc99a1ed10fbe04f44132d9d04885edf1a92e2e16828f825ea167d06")
    private val bSeed = Hex.decode("9493d01d80c72ec0770529a5125cd60fd4bfc19b75662b2ca9ff45a417b344f2")
    private val cSeed = Hex.decode("a033afa007a178f308cdbc9313e532c516b3e5704fb83d3f82f499e3913779b2")
    private val t0 = 1_788_264_000L

    private fun id(seed: ByteArray) = KeyRef.ed25519(pub(seed)).render()

    private class Fleet(val usr: String, val adds: List<String>, val removeC: MembershipOp)

    /** Genesis admits A, B, C (high-water 3, so k = 2); A proposes removing C, alone. */
    private fun fleet(): Fleet {
        val usr = id(genesisSeed)
        val g = signer(genesisSeed)
        val gPub = pub(genesisSeed)
        fun add(dev: ByteArray, prev: String?, at: Long) =
            MembershipOp.sign(g, gPub, usr, MembershipOp.Kind.ADD, id(dev), "", listOfNotNull(prev), at)
        val addA = add(aSeed, null, t0)
        val addB = add(bSeed, MembershipOp.hash(addA), t0 + 60)
        val addC = add(cSeed, MembershipOp.hash(addB), t0 + 120)
        val rm = MembershipOp.sign(
            signer(aSeed),
            pub(aSeed),
            usr,
            MembershipOp.Kind.REMOVE,
            id(cSeed),
            "",
            listOf(MembershipOp.hash(addC)),
            t0 + 600,
        )
        return Fleet(usr, listOf(addA, addB, addC), MembershipOp.verify(rm))
    }

    @Test
    fun aLoneMemberRemoveIsUnderThresholdAtThreeDevices() {
        val f = fleet()
        val view = Membership.evaluate(f.usr, f.adds + f.removeC.token, t0 + 3600)
        assertEquals(Membership.Reason.UNDER_THRESHOLD, view.ineffective[f.removeC.hash])
        assertTrue(view.isMember(id(cSeed)), "C stays: one signature is short of k = 2")
    }

    @Test
    fun aRemoveCosignedHereByASecondMemberTakesEffect() {
        val f = fleet()
        // B, on its own device, co-signs A's proposal; A attaches it and publishes.
        val csB = MembershipOp.cosign(signer(bSeed), pub(bSeed), f.removeC)
        val cosigned = MembershipOp.attachCosigs(signer(aSeed), pub(aSeed), f.removeC, listOf(csB))
        val op = MembershipOp.verify(cosigned)
        assertFalse(op.hash == f.removeC.hash, "the cosigned token is a new op")
        val view = Membership.evaluate(f.usr, f.adds + cosigned, t0 + 3600)
        assertFalse(view.isMember(id(cSeed)), "A + B is k = 2 distinct member signatures")
        assertTrue(id(cSeed) in view.removed)
        assertTrue(op.hash !in view.ineffective && op.hash !in view.rejected)
        assertEquals(setOf(id(aSeed), id(bSeed)), view.members.keys)
    }

    @Test
    fun aSelfCosigOrANonMemberCosigDoesNotCount() {
        val f = fleet()
        // A self-cosig, and a cosig by a non-member key: neither is a SECOND member.
        val self = MembershipOp.cosign(signer(aSeed), pub(aSeed), f.removeC)
        val outsider = MembershipOp.cosign(signer(cosignerSeed), pub(cosignerSeed), f.removeC)
        val cosigned = MembershipOp.attachCosigs(signer(aSeed), pub(aSeed), f.removeC, listOf(self, outsider))
        val view = Membership.evaluate(f.usr, f.adds + cosigned, t0 + 3600)
        assertEquals(Membership.Reason.UNDER_THRESHOLD, view.ineffective[MembershipOp.hash(cosigned)])
        assertTrue(view.isMember(id(cSeed)))
    }
}
