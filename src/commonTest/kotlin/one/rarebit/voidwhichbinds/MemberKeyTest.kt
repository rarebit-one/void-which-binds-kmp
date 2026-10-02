package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * `MemberKey.parse` (void-which-binds-go `identity.ParseMemberKey`, ADR-0018): the two
 * kinds, their one canonical spelling, and every refusal. The Go-minted key-string
 * vectors (`vectors/webauthn/key-*`) are replayed by `WebAuthnVectorTest` too.
 */
class MemberKeyTest {

    private val edKey = "ed25519:03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

    // The P-256 base point G, a valid public point.
    private val gHex = "04" +
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    private val passkey = "webauthn:es256:$gHex"

    @Test
    fun parsesBothKindsCanonically() {
        for ((s, kind) in listOf(edKey to MemberKey.Kind.ED25519, passkey to MemberKey.Kind.WEBAUTHN)) {
            val k = MemberKey.parse(s)
            assertEquals(kind, k.kind, s)
            assertEquals(s, k.toString(), "String() is the parsed spelling")
            assertEquals(k, MemberKey.parse(s))
        }
        assertNotEquals(MemberKey.parse(edKey), MemberKey.parse(passkey))
        assertEquals(passkey, MemberKey.formatWebAuthnEs256(Hex.decode(gHex)))
    }

    @Test
    fun refusesEveryOtherSpelling() {
        val offCurve = gHex.dropLast(1) + "4" // y off by one
        val compressed = "03" + gHex.substring(2, 66)
        val refusals = mapOf(
            "empty" to "",
            "leading space" to " $edKey",
            "trailing newline" to "$edKey\n",
            "no prefix" to "ed25519",
            "bare hex" to gHex,
            "empty webauthn point" to "webauthn:es256:",
            "uppercase ed25519" to "ed25519:" + "A".repeat(64),
            "ed25519 wrong length" to "ed25519:" + "ab".repeat(31),
            "x25519 key" to "x25519:" + "ab".repeat(32),
            "unknown prefix" to "p256:$gHex",
            "webauthn without es256" to "webauthn:$gHex",
            "webauthn wrong sub-algorithm" to "webauthn:es384:$gHex",
            "uppercase point" to "webauthn:es256:" + gHex.uppercase(),
            "short point" to "webauthn:es256:" + gHex.substring(0, 128),
            "compressed point" to "webauthn:es256:$compressed",
            "off curve" to "webauthn:es256:$offCurve",
            "identity" to "webauthn:es256:04" + "00".repeat(64),
            "non-hex" to "webauthn:es256:" + gHex.dropLast(1) + "g",
            "trailing colon segment" to "$passkey:",
        )
        for ((name, s) in refusals) {
            val e = assertFailsWith<MemberKeyException>(name) { MemberKey.parse(s) }
            assertEquals(MemberKeyFailure.MALFORMED_PUBLIC_KEY, e.failure, name)
            assertEquals("malformed", MemberKey.reason(e), name)
        }
    }

    @Test
    fun reasonWords() {
        assertEquals("ok", MemberKey.reason(null))
        assertEquals("malformed", MemberKey.reason(IllegalStateException("unknown")))
        assertEquals(
            listOf(
                "malformed", "malformed", "malformed", "wrong_ceremony", "challenge_mismatch", "origin_not_allowed",
                "rp_id_mismatch", "user_not_present", "user_not_verified", "synced_not_allowed", "bad_signature",
            ),
            MemberKeyFailure.entries.map { it.word },
        )
    }

    @Test
    fun challengeDerivation() {
        // Known answer: SHA-256("void-which-binds/webauthn/challenge/v1" ‖ 0x00 ‖ "d" ‖ 0x00 ‖ "b").
        assertEquals(
            "fa5a44af51804e2e32b9a872d69da834c54207a5745fd82c5d292a3e1119f0f7",
            Hex.encode(WebAuthn.challenge("d", "b".encodeToByteArray())),
        )
        val a = Hex.encode(WebAuthn.challenge("d", "b".encodeToByteArray()))
        assertNotEquals(a, Hex.encode(WebAuthn.challenge("d", "c".encodeToByteArray())))
        assertNotEquals(a, Hex.encode(WebAuthn.challenge("e", "b".encodeToByteArray())))
        // The NUL separators keep (domain, body) unambiguous for NUL-free domains.
        assertNotEquals(
            Hex.encode(WebAuthn.challenge("ab", "c".encodeToByteArray())),
            Hex.encode(WebAuthn.challenge("a", "bc".encodeToByteArray())),
        )
    }
}
