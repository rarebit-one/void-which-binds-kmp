package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.crypto.P256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * void-which-binds-go #116 (v0.19.2): a key has ONE spelling. Every key-bearing field
 * (an op's `usr`, `by`, `dev`, each cosig `by`; a cert's `dev`; an invite's `usr`)
 * must equal its canonical rendering, or a padded / re-cased rendering of one key
 * counts as a second member (an ADR-0008 k=2 bypass, a high-water inflation).
 *
 * [mintersRefuseNonCanonicalKeys] mirrors Go's `TestMintersRefuseNonCanonicalKeys`;
 * the evaluator side is pinned by the `noncanonical-key-rendering-malformed` and
 * `cosig-two-renderings-refused` golden vectors (`MembershipVectorTest`).
 */
class CanonicalKeyTest {

    private fun seed(base: Int) = ByteArray(32) { (base + it).toByte() }
    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private fun pub(seed: ByteArray) = Ed25519Group.publicKeyFromSeed(seed)
    private fun id(seed: ByteArray) = KeyRef.ed25519(pub(seed)).render()

    private val gSeed = seed(0x10)
    private val aSeed = seed(0x40)
    private val bSeed = seed(0x70)
    private val g = id(gSeed)
    private val a = id(aSeed)
    private val b = id(bSeed)

    /** A canonical passkey member: the P-256 base point, SEC1 uncompressed. */
    private val passkey = "webauthn:es256:04" + P256_GX + P256_GY

    private val t0 = 1_788_264_000L
    private val head = listOf(MembershipOp.HASH_PREFIX + "00".repeat(32))

    private fun padded(s: String) = " $s "

    private fun upperHex(s: String): String {
        val i = s.lastIndexOf(':')
        return s.substring(0, i + 1) + s.substring(i + 1).uppercase()
    }

    private fun malformed(block: () -> Unit) {
        assertEquals(MembershipOp.Failure.MALFORMED, assertFailsWith<MembershipOp.OpException> { block() }.failure)
    }

    @Test
    fun mintersRefuseNonCanonicalKeys() {
        val badDevs = mapOf(
            "padded ed25519" to padded(b),
            "trailing newline" to b + "\n",
            "uppercase ed25519" to upperHex(b),
            "uppercase webauthn" to upperHex(passkey),
            "padded webauthn" to padded(passkey),
            "webauthn off-curve" to "webauthn:es256:04" + "00".repeat(64),
            "unknown kind" to "x25519:" + "00".repeat(32),
            "bare hex" to b.removePrefix("ed25519:"),
        )
        for ((name, dev) in badDevs) {
            val e = assertFailsWith<MembershipOp.OpException>("sign dev $name") {
                MembershipOp.sign(signer(aSeed), pub(aSeed), g, MembershipOp.Kind.ADD, dev, "", head, t0)
            }
            assertEquals(MembershipOp.Failure.MALFORMED, e.failure, "sign dev $name")
        }
        // A canonical passkey dev is a member key (ADR-0018).
        MembershipOp.verify(
            MembershipOp.sign(signer(aSeed), pub(aSeed), g, MembershipOp.Kind.ADD, passkey, "", head, t0),
        )

        for ((name, usr) in mapOf("padded" to padded(g), "uppercase" to upperHex(g))) {
            val e = assertFailsWith<MembershipOp.OpException>("sign usr $name") {
                MembershipOp.sign(signer(gSeed), pub(gSeed), usr, MembershipOp.Kind.ADD, a, "", emptyList(), t0)
            }
            assertEquals(MembershipOp.Failure.MALFORMED, e.failure, "sign usr $name")
            // Go: Evaluate returns ErrNoUser.
            assertFailsWith<IllegalArgumentException>("evaluate usr $name") {
                Membership.evaluate(usr, emptyList(), t0)
            }
        }

        val op = MembershipOp.verify(
            MembershipOp.sign(signer(aSeed), pub(aSeed), g, MembershipOp.Kind.REMOVE, b, "", head, t0),
        )
        val cs = MembershipOp.cosign(signer(bSeed), pub(bSeed), op)
        assertTrue(MembershipOp.verifyCosig(op, cs), "canonical cosig")
        for ((name, by) in mapOf("padded" to padded(b), "uppercase" to upperHex(b))) {
            val bad = MembershipOp.Cosig(by = by, sig = cs.sig)
            assertFalse(MembershipOp.verifyCosig(op, bad), "verifyCosig by $name")
            malformed { MembershipOp.attachCosigs(signer(aSeed), pub(aSeed), op, listOf(bad)) }
            malformed { MembershipOp.cosign(signer(bSeed), pub(bSeed), op.copy(device = padded(op.device))) }
            malformed { MembershipOp.cosign(signer(bSeed), pub(bSeed), op.copy(by = by)) }
        }
        MembershipOp.attachCosigs(signer(aSeed), pub(aSeed), op, listOf(cs))
    }

    @Test
    fun verifyRefusesANonCanonicalKeyInASignedOp() {
        // Genuinely signed bodies whose only fault is a key's spelling.
        fun forge(usr: String, by: String, dev: String, signerSeed: ByteArray, cosigBy: String? = null): String {
            val fields = ArrayList<Pair<String, Any>>()
            fields += "v" to 3
            fields += "typ" to TokenType.OP
            fields += "usr" to usr
            fields += "op" to "add"
            fields += "dev" to dev
            fields += "by" to by
            fields += "prev" to head
            if (cosigBy != null) fields += "cosig" to listOf(listOf("by" to cosigBy, "sig" to "AAAA"))
            fields += "iat" to t0
            fields += "exp" to t0 + 3600
            val body = MiniJson.encodeObject(fields).encodeToByteArray()
            return Base64Url.encode(body) + "." + Base64Url.encode(Ed25519Engine.sign(signerSeed, body))
        }
        MembershipOp.verify(forge(g, a, b, aSeed)) // the canonical control
        malformed { MembershipOp.verify(forge(g, a, padded(b), aSeed)) }
        malformed { MembershipOp.verify(forge(g, a, upperHex(b), aSeed)) }
        malformed { MembershipOp.verify(forge(g, a, upperHex(passkey), aSeed)) }
        malformed { MembershipOp.verify(forge(g, padded(a), b, aSeed)) }
        malformed { MembershipOp.verify(forge(g, upperHex(a), b, aSeed)) }
        malformed { MembershipOp.verify(forge(padded(g), a, b, aSeed)) }
        malformed { MembershipOp.verify(forge(upperHex(g), a, b, aSeed)) }
        // Before #116 a non-canonical cosig by was merely ignored; now the op is malformed.
        malformed { MembershipOp.verify(forge(g, a, b, aSeed, cosigBy = padded(b))) }
    }

    @Test
    fun canCosignIsCanonicalOnly() {
        assertTrue(canCosign(a))
        assertFalse(canCosign(padded(a)))
        assertFalse(canCosign(a + "\n"))
        assertFalse(canCosign(upperHex(a)))
        assertFalse(canCosign(passkey))
    }

    @Test
    fun certDeviceMustBeCanonical() {
        fun cert(dev: String): String {
            val denc = "x25519:" + "11".repeat(32)
            val body = """{"v":2,"typ":"${TokenType.CERT}","usr":"$g","dev":"$dev","denc":"$denc",""" +
                """"iat":$t0,"exp":${t0 + 3600}}"""
            val bytes = body.encodeToByteArray()
            return Base64Url.encode(bytes) + "." + Base64Url.encode(Ed25519Engine.sign(gSeed, bytes))
        }
        assertEquals(a, Cert.parse(cert(a)).cert.device.render())
        for (dev in listOf(padded(a), upperHex(a))) {
            assertFailsWith<IllegalArgumentException>("cert dev '$dev'") { Cert.parse(cert(dev)) }
            malformed { MembershipOp.verify(cert(dev)) }
        }
    }

    @Test
    fun inviteUserMustBeCanonical() {
        val salt = ByteArray(32) { 0x33 }
        Invite.decode(Invite.encode("http://r", "s", salt, g))
        assertFailsWith<IllegalArgumentException> { Invite.encode("http://r", "s", salt, " $g") }
        assertFailsWith<IllegalArgumentException> { Invite.encode("http://r", "s", salt, upperHex(g)) }
        val good = Invite.encode("http://r", "s", salt, g)
        val hexPart = g.removePrefix("ed25519:")
        assertFailsWith<IllegalArgumentException> { Invite.decode(good.replace(hexPart, hexPart.uppercase())) }
        assertFailsWith<IllegalArgumentException> { Invite.decode(good.replace("usr=", "usr=+")) }
    }

    @Test
    fun p256PointValidation() {
        val gPoint = Hex.decode("04$P256_GX$P256_GY")
        assertTrue(P256.isValidUncompressedPoint(gPoint))
        // y + 1 is off the curve.
        val off = gPoint.copyOf().also { it[64] = (it[64] + 1).toByte() }
        assertFalse(P256.isValidUncompressedPoint(off))
        // The compressed / hybrid prefixes and wrong lengths are refused.
        assertFalse(P256.isValidUncompressedPoint(gPoint.copyOf().also { it[0] = 0x02 }))
        assertFalse(P256.isValidUncompressedPoint(gPoint.copyOf(64)))
        // A coordinate >= p is not a field element, even if it would reduce onto the curve.
        val p = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        assertFalse(P256.isValidUncompressedPoint(Hex.decode("04$p$P256_GY")))
        assertFalse(P256.isValidUncompressedPoint(Hex.decode("04" + "00".repeat(64))))
        // 2G, a second known point.
        assertTrue(P256.isValidUncompressedPoint(Hex.decode("04$P256_2GX$P256_2GY")))
    }

    private companion object {
        const val P256_GX = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        const val P256_GY = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        const val P256_2GX = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        const val P256_2GY = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
    }
}
