package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.assertMatchesGoToken
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Cross-language golden vectors against the Go implementation relying parties run
 * (void-which-binds-go v0.5.0 `enrolment.SignPossession`). Both vectors were minted by the
 * REAL Go code with fixed seeds and clocks. The JDK's Ed25519 is deterministic, so
 * on JVM/Android a byte-for-byte match proves a proof this library mints is what
 * `enrolment.VerifyPossession` / heyarr's `deviceauth.Verify` accepts. On iOS
 * (randomized CryptoKit Ed25519) the payload must match and both signatures must
 * verify (see [one.rarebit.voidwhichbinds.assertMatchesGoToken]).
 *
 * If a constant ever has to change to make this pass, the wire format broke — stop
 * and investigate. The same vectors, as JSON, live in
 * `src/jvmTest/resources/vectors/` (see `DeviceSchemeVectorTest`).
 */
class PossessionProofTest {

    // Vector A — heyarr-core's own crosscompat golden cert (user seed 0x01*32, device
    // seed 0x02*32, iat 1700000000) + a proof minted by Go `SignPossession(dev, cert,
    // 1700000000, 0)`. Carried over from heyarr-mobile's PossessionProofTest.
    private val certA = "eyJ2IjoyLCJ1c3IiOiJlZDI1NTE5OjhhODhlM2RkNzQwOWYxOTVmZDUyZGIyZDNjYmE1ZDcyY2E2NzA5YmYxZDk0MTIxYmYzNzQ4ODAxYjQwZjZmNWMiLCJkZXYiOiJlZDI1NTE5OjgxMzk3NzBlYTg3ZDE3NWY1NmEzNTQ2NmMzNGM3ZWNjY2I4ZDhhOTFiNGVlMzdhMjVkZjYwZjViOGZjOWIzOTQiLCJkZW5jIjoieDI1NTE5OjAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMwMzAzMDMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwNzc3NjAwMH0.yUnLKnvDZ8YtkgV9zf5eRrYHes5osqzzGlVHXcFSPiuIuVM0jmcdGH4qOQA-UCla_9qwSK7VPpXSfsTbSY_JBA"
    private val proofA = "eyJ2IjoyLCJjcnQiOiJsQ2ViWTBpTTM0SGM0Z3RGUERtZ1o2S0pMWWE0ejc0YklhU1hSWFV1d01ZIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDAxMjB9.2Ta_JOte2RDRHBFrNvOToo68--ea7TIfRjFPNGV-JtvQiXVb_hfE1gQCA9RwlbHyFJ9Mp0AZ5G_u19U1jB-FAg"
    private val deviceSeedA = ByteArray(32) { 0x02 }
    private val nowA = 1_700_000_000L

    // Vector B — the Device-scheme vector minted by a scratch Go test (device seed
    // 0x80..0x9f, cert iat 1788307200, possession now 1788350400); the JSON copy is
    // src/jvmTest/resources/vectors/device-scheme-vector.json.
    private val certB = "eyJ2IjoyLCJ1c3IiOiJlZDI1NTE5OjAzYTEwN2JmZjNjZTEwYmUxZDcwZGQxOGU3NGJjMDk5NjdlNGQ2MzA5YmE1MGQ1ZjFkZGM4NjY0MTI1NTMxYjgiLCJkZXYiOiJlZDI1NTE5OmNkMTRiMzdmOTU2ZTk1MzE5NGZmN2ZiNzNiM2Q4MWRjYzU2MWQ2MWE3NTM4MDk0YjdjM2UxYTY0M2VlNWYzYWEiLCJkZW5jIjoieDI1NTE5OjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZmMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYiLCJpYXQiOjE3ODgzMDcyMDAsImV4cCI6MTc5NjA4MzIwMH0.3VwIUF7Bg1fGQgZ8lwGUvzjpNf2FwoaP-oHcrtleTFaLMiGS2AuljHoBSpOivIl1cJ5ue61_Ci50xX7GPFWCCA"
    private val proofB = "eyJ2IjoyLCJjcnQiOiJJdG01WGo5Vmtta2NkQWNOV3JjNEM0QU1LeVppTmx2cFRZM2dfS2FtakxJIiwiaWF0IjoxNzg4MzUwNDAwLCJleHAiOjE3ODgzNTA1MjB9.Qrj11oz4bLp_Zy8xWcHzQkhvYsjcCdy69LGGRcoCABPnlz3WynYLQwVFuxoVlYkn024FaXIDhXGadMAfR5g5Bw"
    private val deviceSeedB = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    private val nowB = 1_788_350_400L

    // Vector B as minted since ADR-0009 phase 2 (void-which-binds-go
    // device-scheme-vector-typed.json): what PossessionProof.mint emits now.
    private val certBTyped =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkYmluZC5jZXJ0IiwidXNyIjoiZWQyNTUxOTowM2ExMDdiZmYzY2UxMGJlMWQ3MGRkMT" +
            "hlNzRiYzA5OTY3ZTRkNjMwOWJhNTBkNWYxZGRjODY2NDEyNTUzMWI4IiwiZGV2IjoiZWQyNTUxOTpjZDE0YjM3Zjk1" +
            "NmU5NTMxOTRmZjdmYjczYjNkODFkY2M1NjFkNjFhNzUzODA5NGI3YzNlMWE2NDNlZTVmM2FhIiwiZGVuYyI6IngyNT" +
            "UxOTowMDExMjIzMzQ0NTU2Njc3ODg5OWFhYmJjY2RkZWVmZjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZm" +
            "IiwiaWF0IjoxNzg4MzA3MjAwLCJleHAiOjE3OTYwODMyMDB9.ilXUzCfZiDujpgRY-hxOOhDYwIoWdbCvkAVAWsjYp" +
            "HMr3aoanr9POUSqYkYjyS-qIhxnivB-5cpHONzYCpZaAg"

    private val proofBTyped =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkYmluZC5wb3NzZXNzaW9uIiwiY3J0Ijoib2F1UHlXQ2FYckVwWW1mM01tdUM5Q2ppTT" +
            "dLZGxYVGtKaWRjN0o0OG1EUSIsImlhdCI6MTc4ODM1MDQwMCwiZXhwIjoxNzg4MzUwNTIwfQ.bzgcN04eLQxso30rj" +
            "oeCLUO8eGLGIY1WisbnIboa2o5IXvlI-yG8flGSDJl5hHgz_mP2y1yON8RJfkZVo75RAA"

    private val verifier = Ed25519Engine.verifier()
    private fun signer(seed: ByteArray) = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    private fun devicePub(token: String) = Cert.parse(token).cert.device.bytes

    @Test
    fun signingBytesMatchGoJson() {
        assertEquals(
            """{"v":2,"crt":"Itm5Xj9VkmkcdAcNWrc4C4AMKyZiNlvpTY3g_KamjLI","iat":1788350400,"exp":1788350520}""",
            PossessionProof.signingBytesTyped("", certB, nowB, nowB + 120).decodeToString(),
        )
        // Phase 2: the public signingBytes carries typ, second after v.
        assertEquals(
            """{"v":2,"typ":"voidbind.possession","crt":"oauPyWCaXrEpYmf3MmuC9CjiM7KdlXTkJidc7J48mDQ",""" +
                """"iat":1788350400,"exp":1788350520}""",
            PossessionProof.signingBytes(certBTyped, nowB, nowB + 120).decodeToString(),
        )
        assertEquals("lCebY0iM34Hc4gtFPDmgZ6KJLYa4z74bIaSXRXUuwMY", PossessionProof.certHash(certA))
    }

    @Test
    fun mintsTheExactGoProof_vectorA() {
        // A legacy (untyped) Go proof, reproduced through the untyped mint path.
        assertMatchesGoToken(proofA, PossessionProof.mintTyped("", certA, signer(deviceSeedA), nowA), devicePub(certA))
    }

    @Test
    fun mintsTheExactGoProof_vectorB() {
        val legacy = PossessionProof.mintTyped("", certB, signer(deviceSeedB), nowB)
        assertMatchesGoToken(proofB, legacy, devicePub(certB))
        // Phase 2: the public mint emits the typed proof, byte for byte with Go.
        assertMatchesGoToken(proofBTyped, PossessionProof.mint(certBTyped, signer(deviceSeedB), nowB), devicePub(certB))
        // A non-positive ttl means the Go default, as in SignPossession.
        val zeroTtl = PossessionProof.mint(certBTyped, signer(deviceSeedB), nowB, ttlSeconds = 0)
        assertMatchesGoToken(proofBTyped, zeroTtl, devicePub(certB))
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
        assertEquals(PossessionProof.Payload(2, "Itm5Xj9VkmkcdAcNWrc4C4AMKyZiNlvpTY3g_KamjLI", nowB, nowB + 120), p)
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
