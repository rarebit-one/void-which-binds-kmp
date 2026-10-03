package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.auth.PossessionProof
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.roster.Roster
import one.rarebit.voidwhichbinds.roster.RosterException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Every signed token body is decoded as void-which-binds-go's `encoding/json` decodes it
 * (#107): a fraction or exponent in an unknown member is accepted, member names fold onto
 * fields (`"USR"` and `"uſr"` set `usr`; `"ıat"` and `"İAT"` set nothing), the last
 * duplicate wins, `null` leaves a field as it was, a value of the wrong JSON type or a `v`
 * past int64/Int is malformed, and a repeated slice member is decoded into the earlier
 * one's elements. Recovery secrets and SLIP-39 shares split on Go's `unicode.IsSpace`.
 *
 * Every expected verdict below was checked against void-which-binds-go v0.22.0 (c8614e4)
 * with a throwaway Go program feeding the same body shapes to `enrolment.VerifyOp`/`OpUser`,
 * `VerifyCert`, `VerifyPossession`, `pairflow.VerifyRefusal`, `roster.Verify`,
 * `recovery.ParseSecret` and `recovery.CombineShares`.
 */
class GoDecodeTest {

    private class Actor(label: String) {
        val seed: ByteArray = Hex.decode(MembershipOp.hash("go-decode:$label").substring(7))
        val pub: ByteArray = Ed25519Group.publicKeyFromSeed(seed)
        val id: String = KeyRef.ed25519(pub).render()

        fun token(body: String): String {
            val b = body.encodeToByteArray()
            return Base64Url.encode(b) + "." + Base64Url.encode(Ed25519Engine.sign(seed, b))
        }
    }

    private val g = Actor("genesis")
    private val a = Actor("A")
    private val b = Actor("B")
    private val c = Actor("C")
    private val h1 = "sha256:" + "1".repeat(64)
    private val h2 = "sha256:" + "2".repeat(64)

    // ---- enrolment.VerifyOp / OpUser ----

    /** A genesis-signed v3 add of A, with [extra] appended to its members. */
    private fun opBody(extra: String = "") =
        "{\"v\":3,\"typ\":\"void-which-binds.op\",\"usr\":\"${g.id}\",\"op\":\"add\",\"dev\":\"${a.id}\"," +
            "\"by\":\"${g.id}\",\"prev\":[],\"iat\":$T0,\"exp\":${T0 + HOUR}$extra}"

    private fun opMalformed(body: String) {
        val e = assertFailsWith<MembershipOp.OpException>(body) { MembershipOp.verify(g.token(body)) }
        assertEquals(MembershipOp.Failure.MALFORMED, e.failure, body)
    }

    @Test
    fun opAcceptsAnyNumberInAnUnknownMember() {
        for (extra in listOf(",\"x\":1.5", ",\"x\":-0.5E-2,\"y\":[1e3,{\"z\":2.0}]")) {
            val op = MembershipOp.verify(g.token(opBody(extra)))
            assertEquals(a.id, op.device)
            assertEquals(g.id, MembershipOp.user(g.token(opBody(extra))))
        }
    }

    @Test
    fun opRefusesWhatGoScannerRefuses() {
        // A leading zero and a raw control character are syntax errors in Go: VerifyOp
        // and OpUser are both malformed.
        for (body in listOf(opBody(",\"x\":01"), opBody(",\"x\":\"a\u0001\""))) {
            opMalformed(body)
            assertFailsWith<MembershipOp.OpException> { MembershipOp.user(g.token(body)) }
        }
    }

    @Test
    fun opVersionIsAnInt64Literal() {
        // `3.0` is not an int; 4294967299 is an int64 that is not 3 (it must not wrap to 3).
        for (v in listOf("3.0", "4294967299")) {
            val body = opBody().replace("\"v\":3", "\"v\":$v")
            opMalformed(body)
            assertFailsWith<MembershipOp.OpException> { MembershipOp.user(g.token(body)) }
        }
    }

    @Test
    fun opMemberNamesFoldAsGoFoldsThem() {
        for (key in listOf("USR", "uſr")) {
            val body = opBody().replace("\"usr\"", "\"$key\"")
            assertEquals(g.id, MembershipOp.verify(g.token(body)).user)
            assertEquals(g.id, MembershipOp.user(g.token(body)))
        }
        // Dotless and dotted I are not in i's fold set: `iat` stays 0, so VerifyOp is
        // malformed (no issued-at) while OpUser, which never reads iat, accepts.
        for (key in listOf("ıat", "İAT")) {
            val body = opBody().replace("\"iat\"", "\"$key\"")
            opMalformed(body)
            assertEquals(g.id, MembershipOp.user(g.token(body)))
        }
    }

    @Test
    fun opDuplicatesAndNullsDecodeAsGoDoes() {
        // The last duplicate wins, exact or folded; a later `null` keeps the earlier value.
        assertEquals(b.id, MembershipOp.verify(g.token(opBody(",\"DEV\":\"${b.id}\""))).device)
        val exactLast = opBody(",\"dev\":\"${b.id}\"").replaceFirst("\"dev\"", "\"Dev\"")
        assertEquals(b.id, MembershipOp.verify(g.token(exactLast)).device)
        assertEquals(a.id, MembershipOp.verify(g.token(opBody(",\"dev\":null"))).device)
        assertEquals(emptyList(), MembershipOp.verify(g.token(opBody(",\"prev\":[null]"))).prev)
        val remove = MembershipOp.verify(g.token(opBody(",\"OP\":\"remove\",\"EXP\":0")))
        assertEquals(MembershipOp.Kind.REMOVE, remove.kind)
        assertEquals(0L, remove.expiresAt)
    }

    @Test
    fun opWrongJsonTypesRefuseOnlyTheFieldsTheirDecoderReads() {
        // VerifyOp decodes every op field; OpUser decodes only v and usr.
        for (extra in listOf(",\"iat\":1700000000.0", ",\"prev\":5")) {
            opMalformed(opBody(extra))
            assertEquals(g.id, MembershipOp.user(g.token(opBody(extra))))
        }
        opMalformed(opBody(",\"usr\":5"))
        assertFailsWith<MembershipOp.OpException> { MembershipOp.user(g.token(opBody(",\"usr\":5"))) }
    }

    /** A v3 add of B signed by member A, citing [h1], with [extra] appended. */
    private fun memberOp(extra: String) = MembershipOp.verify(
        a.token(
            "{\"v\":3,\"typ\":\"void-which-binds.op\",\"usr\":\"${g.id}\",\"op\":\"add\",\"dev\":\"${b.id}\"," +
                "\"by\":\"${a.id}\",\"prev\":[\"$h1\"],\"iat\":$T0,\"exp\":${T0 + HOUR}$extra}",
        ),
    )

    @Test
    fun opRepeatedSlicesReuseTheirElementsAsGoDoes() {
        // Go decodes a repeated slice member into the slice it already holds: a `null`
        // element, or a cosig object without `sig`, keeps what the earlier member wrote.
        assertEquals(listOf(h2), memberOp(",\"prev\":[\"$h2\",\"$h1\"],\"prev\":[null]").prev)
        assertEquals(listOf(h2), memberOp(",\"prev\":[\"$h1\",\"$h2\"],\"prev\":[\"$h2\"]").prev)
        assertEquals(
            listOf(MembershipOp.Cosig(c.id, "S1"), MembershipOp.Cosig(c.id, "S2")),
            memberOp(
                ",\"cosig\":[{\"by\":\"${b.id}\",\"sig\":\"S1\"},{\"by\":\"${c.id}\",\"sig\":\"S2\"}]," +
                    "\"cosig\":[{\"by\":\"${c.id}\"},null]",
            ).cosig,
        )
        // A `null` member resets the slice, so nothing is reused after it.
        assertEquals(
            listOf(MembershipOp.Cosig(c.id, "")),
            memberOp(
                ",\"cosig\":[{\"by\":\"${b.id}\",\"sig\":\"S1\"}],\"cosig\":null,\"cosig\":[{\"by\":\"${c.id}\"}]",
            ).cosig,
        )
        assertEquals(
            listOf(MembershipOp.Cosig(c.id, "S1")),
            memberOp(",\"COSIG\":[{\"BY\":\"${c.id}\",\"Sig\":\"S1\",\"x\":1.5}]").cosig,
        )
        val e = assertFailsWith<MembershipOp.OpException> { memberOp(",\"cosig\":[\"x\"]") }
        assertEquals(MembershipOp.Failure.MALFORMED, e.failure)
    }

    // ---- enrolment.VerifyCert ----

    private fun certBody(extra: String = "") =
        "{\"v\":2,\"typ\":\"void-which-binds.cert\",\"usr\":\"${g.id}\",\"dev\":\"${a.id}\"," +
            "\"denc\":\"x25519:${"ab".repeat(32)}\",\"iat\":$T0,\"exp\":${T0 + HOUR}$extra}"

    @Test
    fun certDecodesAsVerifyCertDoes() {
        assertEquals(KeyRef.parse(a.id), Cert.parse(g.token(certBody(",\"x\":1.5"))).cert.device)
        assertEquals(KeyRef.parse(g.id), Cert.parse(g.token(certBody().replace("\"usr\"", "\"USR\""))).cert.user)
        assertEquals(KeyRef.parse(b.id), Cert.parse(g.token(certBody(",\"Dev\":\"${b.id}\""))).cert.device)
        assertEquals(0L, Cert.parse(g.token(certBody().replace("\"iat\":$T0,", ""))).cert.issuedAt)
        assertEquals(T0, Cert.parse(g.token(certBody(",\"iat\":null"))).cert.issuedAt)
        for (body in listOf(
            certBody().replace("\"v\":2", "\"v\":2.0"),
            certBody().replace("\"v\":2", "\"v\":4294967298"),
            certBody(",\"x\":01"),
        )) {
            assertFailsWith<IllegalArgumentException>(body) { Cert.parse(g.token(body)) }
        }
    }

    // ---- enrolment.VerifyPossession ----

    private val certToken = g.token(certBody())

    private fun possBody(extra: String = "") =
        "{\"v\":2,\"typ\":\"void-which-binds.possession\",\"crt\":\"${PossessionProof.certHash(certToken)}\"," +
            "\"iat\":$T0,\"exp\":${T0 + POSSESSION_LIFE}$extra}"

    private fun possession(body: String): PossessionProof.Reason? = try {
        PossessionProof.verify(a.token(body), a.pub, certToken, T0 + 60, Ed25519Engine.verifier())
        null
    } catch (e: PossessionProof.Refused) {
        e.reason
    }

    @Test
    fun possessionDecodesAsVerifyPossessionDoes() {
        val m = PossessionProof.Reason.MALFORMED
        val cases = listOf(
            possBody() to null,
            possBody(",\"x\":1.5") to null,
            possBody().replace("\"crt\"", "\"CRT\"") to null,
            possBody().replace("\"iat\":$T0,", "") to null,
            possBody(",\"exp\":null") to null,
            possBody().replace(",\"exp\":${T0 + POSSESSION_LIFE}", "") to PossessionProof.Reason.EXPIRED,
            possBody().replace("\"v\":2", "\"v\":4294967298") to m,
            possBody().replace("\"v\":2", "\"v\":2.0") to m,
            possBody(",\"Typ\":\"void-which-binds.possession\"") to m,
            possBody(",\"x\":01") to m,
            "{\"v\":2,\"typ\":\"void-which-binds.cert\",\"x\":01}" to m,
            "[1]" to m,
            // Go decodes a bare null as an empty map: no typ claim.
            "null" to PossessionProof.Reason.WRONG_TYPE,
        )
        for ((body, want) in cases) assertEquals(want, possession(body), body)
    }

    // ---- pairflow.VerifyRefusal ----

    @Test
    fun refusalReadsExactKeysAsGoDoes() {
        val salt = "salt-0123456789".encodeToByteArray()
        val init = Actor("initiator")
        val head = "{\"v\":1,\"typ\":\"void-which-binds.pair-refusal\",\"by\":\"${init.id}\","
        fun body(extra: String = "") = head + "\"ses\":\"${PairRefusal.session(salt)}\"$extra}"
        fun ok(b: String) = PairRefusal.verify(init.token(b), init.pub, salt)
        assertTrue(ok(body()))
        assertTrue(ok(body(",\"x\":1.5")))
        assertTrue(ok(body(",\"v\":1").replaceFirst("\"v\":1,", "\"v\":2,")))
        assertTrue(ok(body(",\"BY\":\"junk\"")))
        assertFalse(ok(body().replace("\"v\":1", "\"V\":1")))
        assertFalse(ok(body().replace("\"v\":1", "\"v\":1.0")))
        assertFalse(ok(body(",\"v\":null")))
        assertFalse(ok(body(",\"x\":01")))
    }

    // ---- roster.Verify ----

    @Test
    fun rosterReadsTypBeforeAnythingElseAsGoDoes() {
        fun failure(body: String) = assertFailsWith<RosterException>(body) {
            Roster.verify(Base64Url.encode(body.encodeToByteArray()) + ".AA")
        }.failure
        assertEquals(
            RosterException.Failure.WRONG_TYPE,
            failure("{\"v\":1,\"typ\":\"void-which-binds.op\",\"x\":1.5}"),
        )
        for (body in listOf(
            "{\"v\":1,\"typ\":\"void-which-binds.op\",\"x\":01}",
            "{\"v\":1,\"typ\":\"void-which-binds.op\",\"x\":\"\u0001\"}",
            "{\"v\":1,\"typ\":\"void-which-binds.roster\",\"x\":1.5}",
        )) {
            assertEquals(RosterException.Failure.MALFORMED, failure(body), body)
        }
    }

    // ---- recovery.ParseSecret / CombineShares ----

    @Test
    fun recoverySecretSkipsGoWhitespaceOnly() {
        val zero = RecoverySecret.of(ByteArray(32))
        val s = "void-which-binds1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzyal6p"
        assertEquals(zero, RecoverySecret.parse(s))
        for (input in listOf(
            "\u0085$s\u0085",
            s.substring(0, 10) + "\u0085" + s.substring(10),
            s.substring(0, 10) + "\u00A0" + s.substring(10),
            s.substring(0, 10) + "\u3000" + s.substring(10),
        )) {
            assertEquals(zero, RecoverySecret.parse(input))
        }
        for (c in listOf('\u001c', '\u001d', '\u001e', '\u001f')) {
            assertFailsWith<IllegalArgumentException> { RecoverySecret.parse("$c$s") }
        }
    }

    @Test
    fun shareMnemonicsSplitAndLowerAsGoDoes() {
        val zero = RecoverySecret.of(ByteArray(32))
        // A 1-of-1 share of the all-zero secret minted by Go's recovery.SplitShares.
        val share = "firm desert academic academic august olympic negative elevator stadium sled dive " +
            "voter ladle wrap iris cowboy fumes order olympic sugar unhappy grill geology square says " +
            "prize debut device axis humidity olympic roster moisture"
        assertEquals(zero, RecoverySecret.fromShares(listOf(share)))
        for (sep in listOf("\u0085", "\u00A0", "\u3000")) {
            assertEquals(zero, RecoverySecret.fromShares(listOf(share.replace(" ", sep))), "U+%04X".format(sep[0].code))
        }
        // strings.ToLower maps U+0130 to "i" and the Kelvin sign to "k".
        assertEquals(zero, RecoverySecret.fromShares(listOf(share.replace("i", "İ"))))
        assertEquals(zero, RecoverySecret.fromShares(listOf(share.replace("k", "\u212A"))))
        // U+001C is not a Go space: the whole mnemonic is one unknown word.
        assertFailsWith<IllegalArgumentException> { RecoverySecret.fromShares(listOf(share.replace(" ", "\u001c"))) }
    }

    private companion object {
        const val T0 = 1_700_000_000L
        const val HOUR = 3600L
        const val POSSESSION_LIFE = 300L
    }
}
