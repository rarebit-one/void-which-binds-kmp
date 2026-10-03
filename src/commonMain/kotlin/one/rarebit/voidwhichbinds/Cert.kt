package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.GoStruct
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * The enrolment certificate — the signed token an enrolled device presents.
 *
 * Wire shape (byte-identical to void-which-binds-go):
 * ```
 * token = base64url(json payload) + "." + base64url(ed25519 sig)
 * ```
 * The payload is a compact JSON object with fields **in this exact order**
 * (they are signed as-is, so order is part of the contract):
 *
 * | field  | meaning                                   | rendered as        |
 * |--------|-------------------------------------------|--------------------|
 * | `v`    | payload version ([Labels.CERT_VERSION])   | int                |
 * | `typ`  | ADR-0009 token type ([TokenType.CERT])    | `void-which-binds.cert` |
 * | `usr`  | user identity key                         | `ed25519:<hex>`    |
 * | `dev`  | device signing key                        | `ed25519:<hex>`    |
 * | `denc` | device encryption key                     | `x25519:<hex>`     |
 * | `iat`  | issued-at (unix seconds)                  | int                |
 * | `exp`  | expiry (unix seconds)                     | int                |
 *
 * The signature is produced by the *user identity* key over the raw payload
 * JSON bytes.
 */
data class Cert(
    val version: Int,
    val user: KeyRef,
    val device: KeyRef,
    val deviceEnc: KeyRef,
    val issuedAt: Long,
    val expiresAt: Long,
) {
    /**
     * The ADR-0009 `typ` claim, signed second after `v`. Gen2 is typed-only
     * (ADR-0022), so every cert carries [TokenType.CERT].
     */
    val typ: String get() = TokenType.CERT

    init {
        require(user.alg == Labels.ALG_ED25519) { "usr must be ed25519, got ${user.alg}" }
        require(device.alg == Labels.ALG_ED25519) { "dev must be ed25519, got ${device.alg}" }
        require(deviceEnc.alg == Labels.ALG_X25519) { "denc must be x25519, got ${deviceEnc.alg}" }
    }

    /** The exact JSON bytes that are signed (and that `base64url` wraps). */
    fun signingBytes(): ByteArray = MiniJson.encodeObject(
        listOf(
            "v" to version,
            "typ" to typ,
            "usr" to user.render(),
            "dev" to device.render(),
            "denc" to deviceEnc.render(),
            "iat" to issuedAt,
            "exp" to expiresAt,
        ),
    ).encodeToByteArray()

    /** Sign the payload with the user identity key and render the token. */
    fun encode(signer: Ed25519Signer): String {
        val payload = signingBytes()
        val sig = signer.sign(payload)
        return Base64Url.encode(payload) + "." + Base64Url.encode(sig)
    }

    /** Verify the token's signature against this cert's `usr` (user identity) key. */
    fun verify(token: String, verifier: Ed25519Verifier): Boolean {
        val dot = token.indexOf('.')
        if (dot < 0) return false
        val payload = Base64Url.decode(token.substring(0, dot))
        val sig = Base64Url.decode(token.substring(dot + 1))
        return verifier.verify(user.bytes, payload, sig)
    }

    companion object {
        /**
         * The members of void-which-binds-go's cert `payload` that [parse] reads. Its `typ`
         * field is left out: [TokenType.checkTree] has already refused any `typ` (or
         * case variant) that is not a string, so decoding it can never fail.
         */
        private val FIELDS = listOf("v", "usr", "dev", "denc", "iat", "exp")

        /**
         * Parse a token into a [Cert] and its raw signature. Does NOT verify the
         * signature (that needs an [Ed25519Verifier]) — call [Cert.verify] with the
         * same token afterwards.
         *
         * ADR-0009/ADR-0022: `typ` must be [TokenType.CERT]. An absent `typ` (a gen1
         * untyped cert) or any other kind (a gen1 `voidbind.cert` included) throws
         * [TokenType.TypeException] ([TokenType.Failure.WRONG_TYPE]); a malformed
         * `typ` throws it with [TokenType.Failure.MALFORMED].
         *
         * The body is decoded as Go's `json.Unmarshal` into the cert `payload` (#107): an
         * absent or `null` `iat`/`exp` is 0, and an unknown member may hold any JSON.
         */
        @Suppress("ThrowsCount") // one refusal per Go decode step
        fun parse(token: String): Parsed {
            val dot = token.indexOf('.')
            require(dot > 0 && dot < token.length - 1) { "malformed cert token (missing '.')" }
            val payloadBytes = Base64Url.decode(token.substring(0, dot))
            val sig = Base64Url.decode(token.substring(dot + 1))
            // Read as Go's VerifyCert reads it (#107): CheckTyp, then `json.Unmarshal`
            // into `payload` (case-folded names, the last duplicate winning, an absent or
            // `null` field left zero, a value of the wrong JSON type refused).
            val tree = GoStruct.parse(payloadBytes)
            val typ = TokenType.checkTree(tree, TokenType.CERT)
                ?: throw IllegalArgumentException("cert payload is not a JSON object")
            var v = 0L
            var usr = ""
            var dev = ""
            var denc = ""
            var iat = 0L
            var exp = 0L
            try {
                GoStruct.members(tree!!, FIELDS) { f, n ->
                    when (f) {
                        "v" -> v = GoStruct.long(n, v)
                        "usr" -> usr = GoStruct.str(n, usr)
                        "dev" -> dev = GoStruct.str(n, dev)
                        "denc" -> denc = GoStruct.str(n, denc)
                        "iat" -> iat = GoStruct.long(n, iat)
                        else -> exp = GoStruct.long(n, exp)
                    }
                }
            } catch (e: GoStruct.TypeError) {
                throw IllegalArgumentException("cert payload does not decode", e)
            }
            require(v in 1L..Labels.CERT_VERSION.toLong() && TokenType.versionOk(typ, v.toInt())) {
                "a cert is v1 or v2, got v$v"
            }

            // #116: a cert's device is an Ed25519 key in its one canonical spelling; a
            // padded or re-cased rendering would name the same key as a different
            // device (void-which-binds-go enrolment.VerifyCert).
            try {
                KeyRef.parseCanonicalEd25519(dev)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("cert device: ${e.message}", e)
            }
            val cert = Cert(
                version = v.toInt(),
                user = KeyRef.parse(usr),
                device = KeyRef.parse(dev),
                deviceEnc = KeyRef.parse(denc),
                issuedAt = iat,
                expiresAt = exp,
            )
            return Parsed(cert, payloadBytes, sig)
        }
    }

    /** A parsed token: the [cert], the raw signed [payload] bytes, and the [signature]. */
    data class Parsed(val cert: Cert, val payload: ByteArray, val signature: ByteArray) {
        fun verify(verifier: Ed25519Verifier): Boolean = verifier.verify(cert.user.bytes, payload, signature)

        override fun equals(other: Any?): Boolean = other is Parsed && cert == other.cert &&
            payload.contentEquals(other.payload) && signature.contentEquals(other.signature)

        override fun hashCode(): Int {
            var h = cert.hashCode()
            h = 31 * h + payload.contentHashCode()
            h = 31 * h + signature.contentHashCode()
            return h
        }
    }
}
