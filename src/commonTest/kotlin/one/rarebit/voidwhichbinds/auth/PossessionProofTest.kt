package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.TokenType
import one.rarebit.voidwhichbinds.assertMatchesGoToken
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Cross-language golden vectors against the Go implementation relying parties run
 * (void-which-binds-go `enrolment.SignPossession`, gen2: typed-only, ADR-0022). Both
 * vectors were minted by the REAL Go code with fixed seeds and clocks. The JDK's
 * Ed25519 is deterministic, so on JVM/Android a byte-for-byte match proves a proof
 * this library mints is what `enrolment.VerifyPossession` accepts. On iOS
 * (randomized CryptoKit Ed25519) the payload must match and both signatures must
 * verify (see [one.rarebit.voidwhichbinds.assertMatchesGoToken]).
 *
 * If a constant ever has to change to make this pass, the wire format broke — stop
 * and investigate. Vector B, as JSON, lives in
 * `src/jvmTest/resources/vectors/device-scheme-vector.json` (see `DeviceSchemeVectorTest`).
 */
class PossessionProofTest {

    // Vector A — heyarr-core's crosscompat seeds (user seed 0x01*32, device seed
    // 0x02*32, iat 1700000000), minted by void-which-binds-go v0.19.0 `SignCert(user,
    // dev, "x25519:03…", 1700000000, CertLifetime)` + `SignPossession(dev, cert,
    // 1700000000, 0)`.

    @Suppress("MaxLineLength")
    private val certA =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLmNlcnQiLCJ1c3IiOiJlZDI1NTE5OjhhODhlM2RkNzQwOWYxOTVmZDUyZGIyZDNjYmE1ZDcyY2E2NzA5YmYxZDk0MTIxYmYzNzQ4ODAxYjQwZjZmNWMiLCJkZXYiOiJlZDI1NTE5OjgxMzk3NzBlYTg3ZDE3NWY1NmEzNTQ2NmMzNGM3ZWNjY2I4ZDhhOTFiNGVlMzdhMjVkZjYwZjViOGZjOWIzOTQiLCJkZW5jIjoieDI1NTE5OjAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwNzc3NjAwMH0.uD-Q0wQHcmOGISsThInVPUpPCpPbVlDfdUgBY0nAVR3CedGbqstUjJ_1YG1eRQ7V8E_IkU4-uQEi-2tpCD77CA"

    @Suppress("MaxLineLength")
    private val proofA =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLnBvc3Nlc3Npb24iLCJjcnQiOiJrdlhiVWQwQ1hZcmNCbGo4bFJpS2FHTjlmM0w0TENfMHl2cVpNOGJSdUpZIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDAxMjB9.H5jNm9uawkes2ZVWnvXEIgMjAz0JMyPZEbnox-gM-kr-iJ8z_o_mK8-CZ1NOmaAyX7RkWcePov7ipq_v7CoJAg"
    private val deviceSeedA = ByteArray(32) { 0x02 }
    private val nowA = 1_700_000_000L

    // Vector B — void-which-binds-go's device-scheme-vector.json (device seed
    // 0x80..0x9f, cert iat 1788307200, possession now 1788350400).

    @Suppress("MaxLineLength")
    private val certB =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLmNlcnQiLCJ1c3IiOiJlZDI1NTE5OjAzYTEwN2JmZjNjZTEwYmUxZDcwZGQxOGU3NGJjMDk5NjdlNGQ2MzA5YmE1MGQ1ZjFkZGM4NjY0MTI1NTMxYjgiLCJkZXYiOiJlZDI1NTE5OmNkMTRiMzdmOTU2ZTk1MzE5NGZmN2ZiNzNiM2Q4MWRjYzU2MWQ2MWE3NTM4MDk0YjdjM2UxYTY0M2VlNWYzYWEiLCJkZW5jIjoieDI1NTE5OjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZmMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYiLCJpYXQiOjE3ODgzMDcyMDAsImV4cCI6MTc5NjA4MzIwMH0.j8lN2bHcHRnUh-01C9wzZ5MeH6VlquX98QmzHGw210af4sU6_onRYVTwAgHR21XZZCg1wNhzgpnOXni1-c3cCA"

    @Suppress("MaxLineLength")
    private val proofB =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLnBvc3Nlc3Npb24iLCJjcnQiOiJJTVdqZ1BEeFlZcHpEeVQ4RGJQcFBwVENKakJEY2lDc3QzNEdSQWpFUHowIiwiaWF0IjoxNzg4MzUwNDAwLCJleHAiOjE3ODgzNTA1MjB9.m79EwR8_djhsdo4PF2LFgXGptgQP-KWcZ1z9bt7ZHNy0gA9IRWUEZOzKIw5H3nPdlHYSKEqocjLSb90ktoGyAA"
    private val deviceSeedB = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    private val nowB = 1_788_350_400L

    private val verifier = Ed25519Engine.verifier()
    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private fun devicePub(token: String) = Cert.parse(token).cert.device.bytes

    @Test
    fun signingBytesMatchGoJson() {
        // typ is always present, second after v (ADR-0009, ADR-0022).
        assertEquals(
            """{"v":2,"typ":"void-which-binds.possession","crt":"IMWjgPDxYYpzDyT8DbPpPpTCJjBDciCst34GRAjEPz0",""" +
                """"iat":1788350400,"exp":1788350520}""",
            PossessionProof.signingBytes(certB, nowB, nowB + 120).decodeToString(),
        )
        assertEquals("kvXbUd0CXYrcBlj8lRiKaGN9f3L4LC_0yvqZM8bRuJY", PossessionProof.certHash(certA))
    }

    @Test
    fun mintsTheExactGoProof_vectorA() {
        assertMatchesGoToken(proofA, PossessionProof.mint(certA, signer(deviceSeedA), nowA), devicePub(certA))
    }

    @Test
    fun mintsTheExactGoProof_vectorB() {
        assertMatchesGoToken(proofB, PossessionProof.mint(certB, signer(deviceSeedB), nowB), devicePub(certB))
        // A non-positive ttl means the Go default, as in SignPossession.
        val zeroTtl = PossessionProof.mint(certB, signer(deviceSeedB), nowB, ttlSeconds = 0)
        assertMatchesGoToken(proofB, zeroTtl, devicePub(certB))
    }

    @Test
    fun certVectorsVerifyAgainstTheirUserKeyAndNameOurDeviceKey() {
        for (token in listOf(certA, certB)) {
            val parsed = Cert.parse(token)
            assertEquals(2, parsed.cert.version)
            assertTrue(parsed.verify(verifier), "cert signature by usr")
        }
        // The device key the cert names is the one our seed derives — else a proof could never verify.
        assertEquals(
            "ed25519:cd14b37f956e953194ff7fb73b3d81dcc561d61a7538094b7c3e1a643ee5f3aa",
            Cert.parse(certB).cert.device.render(),
        )
    }

    @Test
    fun goProofsVerifyAndParse() {
        val p = PossessionProof.verify(proofB, devicePub(certB), certB, nowB + 1, verifier)
        val want = PossessionProof.Payload(
            version = 2,
            certHash = "IMWjgPDxYYpzDyT8DbPpPpTCJjBDciCst34GRAjEPz0",
            issuedAt = nowB,
            expiresAt = nowB + 120,
            typ = TokenType.POSSESSION,
        )
        assertEquals(want, p)
        assertEquals(p, PossessionProof.parse(proofB))
    }

    @Test
    fun verifyMirrorsGoWindow() {
        val pub = devicePub(certA)
        // honoured 1s before expiry; expired AT ttl (strict); honoured half a skew early; refused 2 skews early
        PossessionProof.verify(proofA, pub, certA, nowA + 119, verifier)
        assertEquals(
            PossessionProof.Reason.EXPIRED,
            refused {
                PossessionProof.verify(proofA, pub, certA, nowA + 120, verifier)
            },
        )
        PossessionProof.verify(proofA, pub, certA, nowA - 15, verifier)
        PossessionProof.verify(proofA, pub, certA, nowA - 30, verifier)
        assertEquals(
            PossessionProof.Reason.NOT_YET_VALID,
            refused {
                PossessionProof.verify(
                    proofA,
                    pub,
                    certA,
                    nowA - 31,
                    verifier,
                )
            },
        )
        assertEquals(
            PossessionProof.Reason.NOT_YET_VALID,
            refused {
                PossessionProof.verify(
                    proofA,
                    pub,
                    certA,
                    nowA - 60,
                    verifier,
                )
            },
        )
    }

    @Test
    fun verifyRefusesWrongCertTamperingAndGarbage() {
        val pub = devicePub(certA)
        assertEquals(
            PossessionProof.Reason.WRONG_CERT,
            refused {
                PossessionProof.verify(proofA, pub, certB, nowA + 1, verifier)
            },
        )
        assertEquals(
            PossessionProof.Reason.BAD_SIGNATURE,
            refused {
                PossessionProof.verify(
                    proofA,
                    devicePub(certB),
                    certA,
                    nowA + 1,
                    verifier,
                )
            },
        )
        val flipped = proofA.substring(0, 5) + (if (proofA[5] == 'A') 'B' else 'A') + proofA.substring(6)
        assertEquals(
            PossessionProof.Reason.BAD_SIGNATURE,
            refused {
                PossessionProof.verify(
                    flipped,
                    pub,
                    certA,
                    nowA + 1,
                    verifier,
                )
            },
        )
        assertEquals(
            PossessionProof.Reason.MALFORMED,
            refused {
                PossessionProof.verify("no-dot", pub, certA, nowA + 1, verifier)
            },
        )
        assertEquals(
            PossessionProof.Reason.MALFORMED,
            refused {
                PossessionProof.verify("!!.!!", pub, certA, nowA + 1, verifier)
            },
        )
        assertEquals(PossessionProof.Reason.MALFORMED, refused { PossessionProof.parse("no-dot") })
    }

    @Test
    fun mintRefusesAnEmptyCertAndANonEd25519Signature() {
        assertFailsWith<IllegalArgumentException> { PossessionProof.mint("", signer(deviceSeedA), nowA) }
        assertFailsWith<IllegalArgumentException> { PossessionProof.mint(certA, Ed25519Signer { ByteArray(63) }, nowA) }
    }

    private fun refused(block: () -> Unit): PossessionProof.Reason =
        assertFailsWith<PossessionProof.Refused> { block() }.reason
}
