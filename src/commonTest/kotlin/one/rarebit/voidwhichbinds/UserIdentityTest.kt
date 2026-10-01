package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.X25519
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The identity spine: a [RecoverySecret] deterministically derives the user
 * Ed25519 key, and that identity self-enrols a device cert a void-which-binds-go relying
 * party accepts. The (secret → public key) vectors are captured from void-which-binds-go's
 * `recovery.DeriveUserSeed` + `ed25519.NewKeyFromSeed`, so this pins the WHOLE
 * kmp chain (HKDF + [crypto.Ed25519Group]) to Go byte-for-byte.
 */
class UserIdentityTest {

    // (recovery secret) -> (user identity public key), captured from void-which-binds-go.
    private val vectors = listOf(
        "void-which-binds1ph3wnlphtjp4ha9j86g0ft6ktvuu4atzyt5hnm8m8905urq5540q40xvf4" to
            "f25f439635e13a556fe6428e26e0b66a0410a8eb1ee11d0af209d5214ac22b15",
        "void-which-binds1qypsvd2nvrvvqktgqjyf5xfmw59sdxzlyynel29q4swlrtpzfdasdycpd6" to
            "6ead54cd58540a1ec9cb7d72d4261bf9adb1247b4573c2ddab07e6a8721d408e",
        "void-which-binds1uetzn4ufrur8f7gdqu5enktfsx3n6wnwueh68vx7vj0psdnzf44ssr0zqr" to
            "88e2cf606c18c3616db99135edf02017fb167d8e3fce4430bcc1cf53aa65051e",
        "void-which-binds1pvgy0ccsg3y0z2vsxzzrazpy79h6r50jvcejvscqqar488cspxnsfrgh6d" to
            "9f87047108839b077f155f4c8d58f26a2e3d2be2bf34bddade2f16d241ccce3e",
    )

    @Test
    fun restoreDerivesTheVoidbindGoPublicKey() {
        for ((secret, pubHex) in vectors) {
            val id = UserIdentity.restore(secret)
            assertEquals(pubHex, Hex.encode(id.userPublicKey), "restored user pub must match Go")
            assertEquals("ed25519:$pubHex", id.userId.render())
        }
    }

    @Test
    fun createThenRestoreRoundTripsToTheSameIdentity() {
        val created = UserIdentity.create()
        val restored = UserIdentity.restore(created.recovery.format())
        assertEquals(
            Hex.encode(created.userPublicKey),
            Hex.encode(restored.userPublicKey),
            "the identity restored from a fresh secret must equal the created one",
        )
    }

    @Test
    fun aMistypedSecretFailsLoudAndDoesNotDeriveAWrongIdentity() {
        // A valid secret with one data-char flipped to another valid charset symbol
        // so the bech32m CHECKSUM (not the charset) is what rejects it.
        val good = vectors[0].first
        val i = good.length - 3
        val flipped = good.substring(0, i) + (if (good[i] == 'q') 'p' else 'q') + good.substring(i + 1)
        assertNotEquals(good, flipped)
        assertFailsWith<IllegalArgumentException> { UserIdentity.restore(flipped) }
    }

    @Test
    fun theGroupedAndUppercaseFormsRestoreTheSameIdentity() {
        val id = UserIdentity.create()
        val raw = id.recovery.format()
        // The backup screen's display form (4-char groups), wrapped across lines as
        // it would be on paper, and the uppercase form a QR code carries.
        val grouped = raw.chunked(4).chunked(4).joinToString("\n") { it.joinToString(" ") }
        for (form in listOf(grouped, raw.uppercase(), grouped.uppercase(), "  $raw\n")) {
            assertContentEquals(id.userPublicKey, UserIdentity.restore(form).userPublicKey, form)
        }
        val mixed = raw.substring(0, raw.length / 2).uppercase() + raw.substring(raw.length / 2)
        assertFailsWith<IllegalArgumentException> { UserIdentity.restore(mixed) }
    }

    @Test
    fun distinctSecretsGiveDistinctIdentities() {
        val a = UserIdentity.restore(vectors[0].first)
        val b = UserIdentity.restore(vectors[1].first)
        assertNotEquals(Hex.encode(a.userPublicKey), Hex.encode(b.userPublicKey))
    }

    @Test
    fun theUserKeySignsAndVerifiesAgainstItsDerivedPublicKey() {
        val id = UserIdentity.restore(vectors[0].first)
        val msg = "void-which-binds identity self-test".encodeToByteArray()
        val sig = id.sign(msg)
        assertTrue(
            Ed25519Engine.verifier().verify(id.userPublicKey, msg, sig),
            "a signature by the derived seed must verify against the derived public key",
        )
    }

    @Test
    fun selfEnrolMintsACertThatVerifiesAgainstTheUserIdentity() {
        val id = UserIdentity.restore(vectors[2].first)
        val enc = DeviceIdentity.generateEncryptionKey()
        // A device signing key (software here; a hardware DeviceKeyStore on-device).
        val deviceSeed = ByteArray(32) { (it + 3).toByte() }
        val device = DeviceIdentity(
            signPublicKey = one.rarebit.voidwhichbinds.crypto.Ed25519Group.publicKeyFromSeed(deviceSeed),
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            signFn = { msg -> Ed25519Engine.sign(deviceSeed, msg) },
        )

        val token = Enrolment.selfEnrol(id, device, issuedAt = 1_800_000_000L, lifetimeSeconds = 3600)
        val parsed = Cert.parse(token)

        assertTrue(parsed.verify(Ed25519Engine.verifier()), "self-enrolled cert must verify")
        assertEquals(id.userId, parsed.cert.user)
        assertEquals(KeyRef.ed25519(device.signPublicKey), parsed.cert.device)
        assertEquals(KeyRef.x25519(enc.publicKey), parsed.cert.deviceEnc)
        assertEquals(Labels.CERT_VERSION, parsed.cert.version)
        assertEquals(1_800_000_000L + 3600, parsed.cert.expiresAt)
    }

    @Test
    fun generatedEncryptionKeyIsAValidX25519Pair() {
        val enc = DeviceIdentity.generateEncryptionKey()
        assertEquals(32, enc.privateKey.size)
        assertEquals(
            Hex.encode(X25519.scalarMultBase(enc.privateKey)),
            Hex.encode(enc.publicKey),
            "the encryption public key must be the base-point multiple of the private scalar",
        )
    }
}
