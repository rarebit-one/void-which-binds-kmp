package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.Base64Url

/**
 * A software ES256 "authenticator" for the WebAuthn tests (a port of
 * void-which-binds-go `internal/webauthntest`), minting assertions with the
 * provider's ECDSA. The key is fresh per instance, so it mints signatures, not
 * golden bytes; the Go-minted goldens are replayed by `WebAuthnVectorTest` (jvmTest).
 */
internal class TestPasskey(var rpId: String = RP_ID, var origin: String = ORIGIN) {
    private val pair = CryptographyProvider.Default.get(ECDSA).keyPairGenerator(EC.Curve.P256).generateKeyBlocking()

    /** The SEC1 uncompressed point. */
    val point: ByteArray = pair.publicKey.encodeToByteArrayBlocking(EC.PublicKey.Format.RAW)

    val keyString: String = MemberKey.formatWebAuthnEs256(point)

    val key: MemberKey get() = MemberKey.parse(keyString)

    var flags: Int = FLAG_UP or FLAG_UV
    var signCount: Int = 42
    var extensions: ByteArray = ByteArray(0)

    fun authData(): ByteArray = sha256(rpId.encodeToByteArray()) +
        byteArrayOf(flags.toByte()) +
        byteArrayOf(
            (signCount ushr 24).toByte(),
            (signCount ushr 16).toByte(),
            (signCount ushr 8).toByte(),
            signCount.toByte(),
        ) +
        extensions

    fun sign(authData: ByteArray, clientData: ByteArray): ByteArray = pair.privateKey
        .signatureGenerator(SHA256, ECDSA.SignatureFormat.DER)
        .generateSignatureBlocking(authData + sha256(clientData))

    /** The envelope (the base64url-decoded signature segment) for these bytes, correctly signed. */
    fun complete(authData: ByteArray, clientData: ByteArray): ByteArray =
        envelope(authData, clientData, sign(authData, clientData))

    fun assert(domain: String, body: ByteArray): ByteArray =
        complete(authData(), clientData("webauthn.get", WebAuthn.challenge(domain, body), origin))

    companion object {
        const val RP_ID = "broker.example"
        const val ORIGIN = "https://broker.example"
        const val DELEGATION = "void-which-binds.delegation"

        const val FLAG_UP = 0x01
        const val FLAG_UV = 0x04
        const val FLAG_BE = 0x08
        const val FLAG_BS = 0x10
        const val FLAG_AT = 0x40
        const val FLAG_ED = 0x80

        val policy = WebAuthnPolicy(listOf(WebAuthnRp(RP_ID, listOf(ORIGIN))))

        private val hasher = CryptographyProvider.Default.get(SHA256).hasher()

        fun sha256(b: ByteArray): ByteArray = hasher.hashBlocking(b)

        fun b64(b: ByteArray): String = Base64Url.encode(b)

        /** Go `webauthntest.ClientData`. */
        fun clientData(type: String, challenge: ByteArray, origin: String, tail: String = ""): ByteArray =
            """{"type":"$type","challenge":"${b64(challenge)}","origin":"$origin","crossOrigin":false$tail}"""
                .encodeToByteArray()

        fun envelope(authData: ByteArray, clientData: ByteArray, sig: ByteArray): ByteArray =
            """{"ad":"${b64(authData)}","cd":"${b64(clientData)}","sig":"${b64(sig)}"}""".encodeToByteArray()
    }
}
