package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The membership op's wire contract, pinned against void-which-binds-go's (gen2, ADR-0022)
 * `genesis-a-b` golden vector: re-signing the vector's ops from its (test-only)
 * seeds must reproduce the exact TOKENS and HASHES the Go side minted. The JDK's
 * Ed25519 is deterministic, so on JVM/Android any byte of drift in the payload
 * encoding shows up here as a different token. CryptoKit (iOS) signs with randomized
 * Ed25519, so there the payload must match exactly and both signatures must verify
 * (see [assertMatchesGoToken]). Then the structural rules `VerifyOp` enforces.
 */
class MembershipOpTest {

    // From testvectors/vectors/membership/genesis-a-b.json (void-which-binds-go, test-only keys).
    private val usr = "ed25519:5c167ac159feac80a76906ae94f7afe328e1aea2752cddee0c641661ec99535d"
    private val genesisSeed = Hex.decode("b683c7c89a94432a50b03b212fc8a8512f56b7e9e3c90a1661276e6ef672eb15")
    private val aSeed = Hex.decode("aa4ef871a1e26955f4273eb857e17a476864d12c84b54180112753bafe845571")
    private val aId = "ed25519:e592a07d7f478013038e471ef2c960f2ba4163fdb993eb917c46120d1df6b945"
    private val aEnc = "x25519:3e99c2f9a2a927bba84c62c19fb01c6e4c778b9b79450eac781a360f57b783ec"
    private val bId = "ed25519:99c686cb1bde1ce694c03d507de25901e70cba4e0204eb1cd7539f5bbbcd27f4"
    private val bEnc = "x25519:3217f637677bc98b06daa4ea850e6623f9d16e941c9d4acfe2c985c78d379768"

    @Suppress("MaxLineLength")
    private val addAToken =
        "eyJ2IjozLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLm9wIiwidXNyIjoiZWQyNTUxOTo1YzE2N2FjMTU5ZmVhYzgwYTc2OTA2YWU5NGY3YWZlMzI4ZTFhZWEyNzUyY2RkZWUwYzY0MTY2MWVjOTk1MzVkIiwib3AiOiJhZGQiLCJkZXYiOiJlZDI1NTE5OmU1OTJhMDdkN2Y0NzgwMTMwMzhlNDcxZWYyYzk2MGYyYmE0MTYzZmRiOTkzZWI5MTdjNDYxMjBkMWRmNmI5NDUiLCJkZW5jIjoieDI1NTE5OjNlOTljMmY5YTJhOTI3YmJhODRjNjJjMTlmYjAxYzZlNGM3NzhiOWI3OTQ1MGVhYzc4MWEzNjBmNTdiNzgzZWMiLCJieSI6ImVkMjU1MTk6NWMxNjdhYzE1OWZlYWM4MGE3NjkwNmFlOTRmN2FmZTMyOGUxYWVhMjc1MmNkZGVlMGM2NDE2NjFlYzk5NTM1ZCIsInByZXYiOltdLCJpYXQiOjE3ODgyNjQwMDAsImV4cCI6MTc5NjA0MDAwMH0.lRhU33D4Q5hyZ9n83VZ7GmnjQDyV-D92u5RYAoQS9R8BMeQOMvuRsSGjpsAidEcU6VyV-iQd1D_xrgkJsyoUAg"

    @Suppress("MaxLineLength")
    private val addBToken =
        "eyJ2IjozLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLm9wIiwidXNyIjoiZWQyNTUxOTo1YzE2N2FjMTU5ZmVhYzgwYTc2OTA2YWU5NGY3YWZlMzI4ZTFhZWEyNzUyY2RkZWUwYzY0MTY2MWVjOTk1MzVkIiwib3AiOiJhZGQiLCJkZXYiOiJlZDI1NTE5Ojk5YzY4NmNiMWJkZTFjZTY5NGMwM2Q1MDdkZTI1OTAxZTcwY2JhNGUwMjA0ZWIxY2Q3NTM5ZjViYmJjZDI3ZjQiLCJkZW5jIjoieDI1NTE5OjMyMTdmNjM3Njc3YmM5OGIwNmRhYTRlYTg1MGU2NjIzZjlkMTZlOTQxYzlkNGFjZmUyYzk4NWM3OGQzNzk3NjgiLCJieSI6ImVkMjU1MTk6ZTU5MmEwN2Q3ZjQ3ODAxMzAzOGU0NzFlZjJjOTYwZjJiYTQxNjNmZGI5OTNlYjkxN2M0NjEyMGQxZGY2Yjk0NSIsInByZXYiOlsic2hhMjU2OjZhMjNlYmJkY2M3ODc5ODUyZDUyOGQwYjU4YzkxMTkyZmRhYWVhZDBjZjcyZmM4NTk0NGE4ZGE2ZGI0NTA0NWIiXSwiaWF0IjoxNzg4MjY0MzAwLCJleHAiOjE3OTYwNDAzMDB9.dmso4rWo1zZZSLyaP6YoAx23elwht4yzeh0Q25B3U4a5rvhoWuDwVvEPNWuTi2Qz-WfJDH8Do9Qb0kTlZ05tDQ"
    private val addAHash = "sha256:6a23ebbdcc7879852d528d0b58c91192fdaaead0cf72fc85944a8da6db45045b"
    private val addBHash = "sha256:1c38c323bf04875e4ee674d289a772d569c249d9303d617b61e00bb9f3dc4de5"

    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private fun pub(seed: ByteArray) = Ed25519Group.publicKeyFromSeed(seed)

    @Test
    fun genesisAddReproducesTheGoTokenByteForByte() {
        assertEquals(usr, KeyRef.ed25519(pub(genesisSeed)).render(), "genesis seed must derive the vector's usr")
        val tok = MembershipOp.sign(
            signer(genesisSeed), pub(genesisSeed), usr, MembershipOp.Kind.ADD, aId, aEnc,
            prev = emptyList(), issuedAt = 1_788_264_000L, lifetimeSeconds = 90L * 24 * 3600,
        )
        assertMatchesGoToken(addAToken, tok, pub(genesisSeed), "the KMP-minted genesis add must equal Go's token")
        assertEquals(addAHash, MembershipOp.hash(addAToken))
        if (ed25519SigningIsDeterministic) assertEquals(addAHash, MembershipOp.hash(tok))
    }

    @Test
    fun memberAddCitingHeadsReproducesTheGoHash() {
        assertEquals(aId, KeyRef.ed25519(pub(aSeed)).render())
        val tok = MembershipOp.sign(
            signer(aSeed), pub(aSeed), usr, MembershipOp.Kind.ADD, bId, bEnc,
            prev = listOf(addAHash), issuedAt = 1_788_264_300L, lifetimeSeconds = 90L * 24 * 3600,
        )
        assertMatchesGoToken(addBToken, tok, pub(aSeed), "the KMP-minted add-B must equal Go's token")
        assertEquals(addBHash, MembershipOp.hash(addBToken), "add-B must hash to the vector's hash")
        if (ed25519SigningIsDeterministic) assertEquals(addBHash, MembershipOp.hash(tok))
        val op = MembershipOp.verify(tok)
        assertEquals(MembershipOp.Kind.ADD, op.kind)
        assertEquals(aId, op.by)
        assertEquals(listOf(addAHash), op.prev)
        assertEquals(1_796_040_300L, op.expiresAt)
        assertTrue(!op.genesis)
    }

    @Test
    fun verifyReadsTheGoTokenAndRefusesATamperedOne() {
        val op = MembershipOp.verify(addAToken)
        assertEquals(addAHash, op.hash)
        assertEquals(3, op.version)
        assertEquals(usr, op.user)
        assertEquals(usr, op.by)
        assertTrue(op.genesis)
        assertEquals(aId, op.device)
        assertEquals(aEnc, op.deviceEnc)
        assertEquals(emptyList(), op.prev)
        assertEquals(1_788_264_000L, op.issuedAt)
        assertEquals(usr, MembershipOp.user(addAToken))

        // One signature byte flipped (the vector's "tampered-sig" case) → BAD_SIGNATURE.
        val tampered = addAToken.replace(".lRhU3", ".lRhA3")
        val e = assertFailsWith<MembershipOp.OpException> { MembershipOp.verify(tampered) }
        assertEquals(MembershipOp.Failure.BAD_SIGNATURE, e.failure)
    }

    @Test
    fun aV2CertIsAGenesisAddWithNoPrev() {
        val user = UserIdentity.create()
        val dev = Ed25519Engine.generate()
        val enc = ByteArray(32) { (it + 3).toByte() }
        val cert = Cert(
            version = Labels.CERT_VERSION,
            user = user.userId,
            device = KeyRef.ed25519(dev.publicKey),
            deviceEnc = KeyRef.x25519(enc),
            issuedAt = 1_788_264_000L,
            expiresAt = 1_796_040_000L,
        ).encode(user.signer())
        val op = MembershipOp.verify(cert)
        assertEquals(2, op.version)
        assertEquals(MembershipOp.Kind.ADD, op.kind)
        assertEquals(user.userId.render(), op.user)
        assertEquals(user.userId.render(), op.by)
        assertTrue(op.genesis)
        assertEquals(KeyRef.ed25519(dev.publicKey).render(), op.device)
        assertEquals(KeyRef.x25519(enc).render(), op.deviceEnc)
        assertEquals(emptyList(), op.prev)
        assertEquals(1_796_040_000L, op.expiresAt)
        assertEquals(MembershipOp.hash(cert), op.hash)

        // And evaluating that one cert finds the device a member — the migration path.
        val view = Membership.evaluate(user.userId.render(), listOf(cert), now = 1_788_267_600L)
        assertTrue(view.isMember(op.device))
        assertEquals(op.hash, view.members.getValue(op.device).admittedBy)
        assertEquals(listOf(op.hash), view.heads)
    }

    @Test
    fun structuralRefusals() {
        val g = signer(genesisSeed)
        val gp = pub(genesisSeed)
        // A member-signed op with no prev.
        assertEquals(
            MembershipOp.Failure.NO_PREV,
            assertFailsWith<MembershipOp.OpException> {
                MembershipOp.sign(signer(aSeed), pub(aSeed), usr, MembershipOp.Kind.ADD, bId, bEnc, emptyList(), 1L)
            }.failure,
        )
        // Genesis can never be a device.
        assertEquals(
            MembershipOp.Failure.GENESIS,
            assertFailsWith<MembershipOp.OpException> {
                MembershipOp.sign(g, gp, usr, MembershipOp.Kind.REMOVE, usr, "", emptyList(), 1L)
            }.failure,
        )
        // A remove carries no denc and no exp; prev is sorted + de-duplicated.
        val rm = MembershipOp.sign(
            g,
            gp,
            usr,
            MembershipOp.Kind.REMOVE,
            aId,
            "ignored?",
            listOf(addBHash, addAHash, addAHash),
            1_788_264_400L,
        )
        val op = MembershipOp.verify(rm)
        assertEquals(MembershipOp.Kind.REMOVE, op.kind)
        assertEquals("", op.deviceEnc)
        assertEquals(0L, op.expiresAt)
        assertEquals(listOf(addBHash, addAHash).sorted(), op.prev)
        // Junk.
        assertEquals(
            MembershipOp.Failure.MALFORMED,
            assertFailsWith<MembershipOp.OpException> {
                MembershipOp.verify("not-an-op")
            }.failure,
        )
        assertEquals(
            MembershipOp.Failure.MALFORMED,
            assertFailsWith<MembershipOp.OpException> {
                MembershipOp.verify("AAAA.BBBB")
            }.failure,
        )
        assertFailsWith<MembershipOp.OpException> { MembershipOp.user("nope") }
    }

    @Test
    fun mergeDeduplicatesByHashInHashOrder() {
        val merged = Membership.merge(listOf(addAToken, ""), listOf(addAToken), listOf(" $addAToken"))
        // The trimmed and untrimmed spellings hash differently (Go hashes the raw token in Merge too).
        assertEquals(2, merged.size)
        assertEquals(merged.map { MembershipOp.hash(it) }.sorted(), merged.map { MembershipOp.hash(it) })
    }
}
