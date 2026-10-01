package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The membership op's wire contract, pinned against void-which-binds-go v0.9.0's
 * `genesis-a-b` golden vector: re-signing the vector's ops from its (test-only)
 * seeds must reproduce the exact TOKENS and HASHES the Go side minted. The JDK's
 * Ed25519 is deterministic, so on JVM/Android any byte of drift in the payload
 * encoding shows up here as a different token. CryptoKit (iOS) signs with randomized
 * Ed25519, so there the payload must match exactly and both signatures must verify
 * (see [assertMatchesGoToken]). Then the structural rules `VerifyOp` enforces.
 */
class MembershipOpTest {

    // From testvectors/vectors/membership/genesis-a-b.json (void-which-binds-go, test-only keys).
    private val usr = "ed25519:f947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4"
    private val genesisSeed = Hex.decode("c24bb87672097fd3292251030126197ba061ffb69b9b67b0786318f627fb132c")
    private val aSeed = Hex.decode("5a855e9adc99a1ed10fbe04f44132d9d04885edf1a92e2e16828f825ea167d06")
    private val aId = "ed25519:44f255376bd10821f82b0f9f568504caaf6c1583c65e685d66d05ec3aac3d789"
    private val aEnc = "x25519:99e1e58af901d759e6969fefe3c3fa47d9cdef954ab64e21fc990c5bae45d35c"
    private val bId = "ed25519:ce9c83f13c6a06666665e0471d45c0b4d4107d892e8ddb4de7ac27520e36f37d"
    private val bEnc = "x25519:32338a06d4f67a664fcaabbf1e98c1e46f2b5750f2270bd4af127355ed560619"
    private val addAToken =
        "eyJ2IjozLCJ1c3IiOiJlZDI1NTE5OmY5NDdiMTBjODA4OWFhOGZlZDJkNDM1ZmFlMDY5ZDBjYTE1MTNiMzM2OTE5NTVhZTk2M2RmZThiYzViMzk4YzQiLCJvcCI6ImFkZCIsImRldiI6ImVkMjU1MTk6NDRmMjU1Mzc2YmQxMDgyMWY4MmIwZjlmNTY4NTA0Y2FhZjZjMTU4M2M2NWU2ODVkNjZkMDVlYzNhYWMzZDc4OSIsImRlbmMiOiJ4MjU1MTk6OTllMWU1OGFmOTAxZDc1OWU2OTY5ZmVmZTNjM2ZhNDdkOWNkZWY5NTRhYjY0ZTIxZmM5OTBjNWJhZTQ1ZDM1YyIsImJ5IjoiZWQyNTUxOTpmOTQ3YjEwYzgwODlhYThmZWQyZDQzNWZhZTA2OWQwY2ExNTEzYjMzNjkxOTU1YWU5NjNkZmU4YmM1YjM5OGM0IiwicHJldiI6W10sImlhdCI6MTc4ODI2NDAwMCwiZXhwIjoxNzk2MDQwMDAwfQ._6NQ53HSNPWvzQQVNbB2mEnGBwI__2fDvZ50OOMbiNGoFDPLPDSunF4ntlIvf3xnexcx8YAqCShYTszzC7KcDw"
    private val addBToken =
        "eyJ2IjozLCJ1c3IiOiJlZDI1NTE5OmY5NDdiMTBjODA4OWFhOGZlZDJkNDM1ZmFlMDY5ZDBjYTE1MTNiMzM2OTE5NTVhZTk2M2RmZThiYzViMzk4YzQiLCJvcCI6ImFkZCIsImRldiI6ImVkMjU1MTk6Y2U5YzgzZjEzYzZhMDY2NjY2NjVlMDQ3MWQ0NWMwYjRkNDEwN2Q4OTJlOGRkYjRkZTdhYzI3NTIwZTM2ZjM3ZCIsImRlbmMiOiJ4MjU1MTk6MzIzMzhhMDZkNGY2N2E2NjRmY2FhYmJmMWU5OGMxZTQ2ZjJiNTc1MGYyMjcwYmQ0YWYxMjczNTVlZDU2MDYxOSIsImJ5IjoiZWQyNTUxOTo0NGYyNTUzNzZiZDEwODIxZjgyYjBmOWY1Njg1MDRjYWFmNmMxNTgzYzY1ZTY4NWQ2NmQwNWVjM2FhYzNkNzg5IiwicHJldiI6WyJzaGEyNTY6OTY0NmI0OTFiNzNlMDYwYzUxYmRkOWUzYjY5Yjg5ZWE4M2ZjMmU1YTY2YzNiMzUxNDFlYzFlMGM1NzhhOGZjNyJdLCJpYXQiOjE3ODgyNjQzMDAsImV4cCI6MTc5NjA0MDMwMH0.xpU7mECpsz-GUYhnwB_26ZyyoT-p0e0en9DGpVri26K-cQmVVrfQcsDP9CYrRXXpzAtm5svBsqaI-JC8azuACg"
    private val addAHash = "sha256:9646b491b73e060c51bdd9e3b69b89ea83fc2e5a66c3b35141ec1e0c578a8fc7"
    private val addBHash = "sha256:3503aea8cf10165ea2417483b66b453610ba07a3c2a1b87c75898e3bb1202d0b"

    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private fun pub(seed: ByteArray) = Ed25519Group.publicKeyFromSeed(seed)

    @Test
    fun genesisAddReproducesTheGoTokenByteForByte() {
        assertEquals(usr, KeyRef.ed25519(pub(genesisSeed)).render(), "genesis seed must derive the vector's usr")
        // genesis-a-b is legacy (untyped) history: reproduce it through the untyped path.
        // The public sign emits typ since ADR-0009 phase 2 (see TypVectorTest).
        val tok = MembershipOp.signTyped(
            "",
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
        val tok = MembershipOp.signTyped(
            "",
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
        val tampered = addAToken.replace("._6NQ53", "._6NA53")
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
