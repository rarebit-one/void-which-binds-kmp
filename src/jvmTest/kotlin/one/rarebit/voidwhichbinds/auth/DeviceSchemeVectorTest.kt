package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.DeviceKeyStore
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.asSigner
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Replays `src/jvmTest/resources/vectors/device-scheme-vector.json` — the Device
 * authorization-scheme vector minted by a scratch Go test against void-which-binds-go v0.5.0
 * `enrolment` (see the README beside it for attribution) — byte-for-byte through the
 * library: cert hash, signing bytes, proof, `<cert>~<proof>` credential and the full
 * `Authorization` header. Then proves the same path through the real `DeviceKeyStore`
 * seam an app uses (a JVM software key here; the sealed hardware key on a phone).
 *
 * That file is the LEGACY (untyped) credential, reproduced through the untyped mint
 * path. `device-scheme-vector-typed.json` is the same credential as minted since
 * ADR-0009 phase 2 (`typ` in the cert and the proof). The public minters
 * ([PossessionProof.mint], [DeviceCredential.mint], a new [Cert]) must produce
 * exactly that file.
 */
class DeviceSchemeVectorTest {

    private fun load(name: String): Map<String, Any> = MiniJson.parseObject(
        checkNotNull(javaClass.getResourceAsStream("/vectors/$name")) {
            "vector resource $name missing"
        }.readBytes().decodeToString(),
    )

    private val vector = load("device-scheme-vector.json")
    private val typed = load("device-scheme-vector-typed.json")

    private fun str(k: String) = vector[k] as String
    private fun num(k: String) = vector[k] as Long
    private fun typedStr(k: String) = typed[k] as String

    private val cert = str("cert")
    private val now = num("possession_now_unix")
    private val deviceSeed = Hex.decode(str("device_seed_hex"))
    private val signer = Ed25519Signer { Ed25519Engine.sign(deviceSeed, it) }

    @Test
    fun certVectorIsSelfConsistent() {
        val parsed = Cert.parse(cert)
        assertEquals(str("cert_payload_json"), parsed.payload.decodeToString())
        assertEquals(str("user_public_key"), parsed.cert.user.render())
        assertEquals(str("device_public_key"), parsed.cert.device.render())
        assertEquals(str("device_encryption_key"), parsed.cert.deviceEnc.render())
        assertEquals(num("cert_issued_at_unix"), parsed.cert.issuedAt)
        assertEquals(num("cert_expires_at_unix"), parsed.cert.expiresAt)
        assertTrue(parsed.verify(Ed25519Engine.verifier()), "cert is signed by usr")
    }

    @Test
    fun possessionProofMatchesTheGoBytes() {
        val payloadJson = str("possession_payload_json")
        val expected = MiniJson.parseObject(payloadJson)
        assertEquals(expected["crt"], PossessionProof.certHash(cert))
        assertEquals(payloadJson, PossessionProof.signingBytesTyped("", cert, now, now + 120).decodeToString())

        val proof = PossessionProof.mintTyped("", cert, signer, now)
        assertEquals(str("possession_proof"), proof)
        assertEquals(str("possession_signature_b64url"), proof.substringAfter('.'))
    }

    @Test
    fun publicMintersProduceTheTypedGoBytes() {
        val typedCert = typedStr("cert")
        val payload = PossessionProof.signingBytes(typedCert, now, now + 120).decodeToString()
        assertEquals(typedStr("possession_payload_json"), payload)
        assertEquals(typedStr("possession_proof"), PossessionProof.mint(typedCert, signer, now))
        // A new Cert (default typ) signed by the user key is Go's typed cert.
        val c = Cert.parse(cert).cert
        val userSeed = Hex.decode(str("user_seed_hex"))
        val fresh = Cert(c.version, c.user, c.device, c.deviceEnc, c.issuedAt, c.expiresAt)
        assertEquals(typedCert, fresh.encode(Ed25519Signer { Ed25519Engine.sign(userSeed, it) }))
        assertEquals(typedStr("cert_payload_json"), Cert.parse(typedCert).payload.decodeToString())
    }

    @Test
    fun credentialAndHeaderMatchTheGoBytes() {
        val p = DeviceCredential.mint(typedStr("cert"), signer, now)
        assertEquals(typedStr("credential"), p.value)
        assertEquals("Authorization: " + p.headerValue, typedStr("authorization_header"))

        val (c, pr) = DeviceCredential.parse(str("credential"))
        assertEquals(cert, c)
        assertEquals(str("possession_proof"), pr)
    }

    @Test
    fun goProofVerifiesAtTheVectorClockAndExpiresStrictly() {
        val devicePub = Cert.parse(cert).cert.device.bytes
        val v = Ed25519Engine.verifier()
        PossessionProof.verify(str("possession_proof"), devicePub, cert, now, v)
        PossessionProof.verify(str("possession_proof"), devicePub, cert, now + 119, v)
        val refused = runCatching { PossessionProof.verify(str("possession_proof"), devicePub, cert, now + 120, v) }
            .exceptionOrNull() as PossessionProof.Refused
        assertEquals(PossessionProof.Reason.EXPIRED, refused.reason)
    }

    @Test
    fun theDeviceKeyStoreSeamMintsAVerifiableCredential() {
        // What an app does: DeviceKeyStore.asSigner() is the signer; the cert names
        // the store's public key. The JVM store is software, but the seam is the same.
        val store = DeviceKeyStore.getOrCreate("device-scheme-vector-test")
        val cred = DeviceCredential(cert, store.asSigner(), { now })
        val header = cred.headerValue()
        val (_, proof) = DeviceCredential.parse(header)
        PossessionProof.verify(proof, store.publicKey().bytes, cert, now + 1, Ed25519Engine.verifier())
    }
}
