package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * A **membership op** — the v3 successor of the enrolment [Cert] (void-which-binds-go
 * `enrolment/op.go`, ADR-0007). Where a v1/v2 cert is "the user root vouches for
 * device D", an op is "member M says D is added / removed", carrying the causal
 * evidence (`prev`) that M was a member when it said so. An identity is no longer
 * one key that signs for everything; it is a SET of device keys, any of which can
 * admit or remove another, with the genesis key (derived from the recovery secret —
 * the `usr` every relying party pins) as a dormant, permanent, un-removable member
 * that only recovery ever signs with.
 *
 * Wire shape — byte-identical to void-which-binds-go, deliberately the cert's so the
 * `Device <op>~<proof>` credential and the possession proof's `sha256(token)`
 * binding survive unchanged:
 * ```
 * payload  {v:3, typ?, usr, op:"add"|"remove", dev, denc?, by, prev:[opHash…], cosig?:[{by,sig}…], iat, exp?}
 * token    b64url(payload) "." b64url(ed25519.Sign(by, payload))
 * hash     "sha256:" hex(sha256(token))
 * ```
 * The payload is compact JSON with the fields in exactly that order (they are
 * signed as-is). `typ` (ADR-0009: `voidbind.op`, second after `v`), `denc`, `cosig`
 * and `exp` are omitted when empty/zero, matching
 * Go's `omitempty`; `prev` is always present (`[]` when empty), sorted and
 * de-duplicated so equal head sets sign to equal bytes.
 *
 * **A v1/v2 cert IS a v3 op** — an add signed by genesis (`by = usr`) with no
 * `prev` — and [verify] reads it as one, so nothing already issued is reissued.
 */
data class MembershipOp(
    /** [HASH_PREFIX] + hex(sha256(token)) — the id other ops cite in `prev`. */
    val hash: String,
    val token: String,
    val version: Int,
    /** The identity (genesis key) this op belongs to, rendered `ed25519:<hex>`. */
    val user: String,
    val kind: Kind,
    /** The device the op adds or removes, rendered `ed25519:<hex>`. */
    val device: String,
    /** The device's X25519 encryption key (`x25519:<hex>`) for an add; empty for a remove or a v1 add. */
    val deviceEnc: String,
    /** The signer's rendered key — equal to [user] for a genesis-signed op. */
    val by: String,
    /** Op hashes the signer cited as its heads (sorted, de-duplicated). */
    val prev: List<String>,
    /**
     * Co-signatures over the op's CORE by second members — the mechanism of
     * ADR-0008's k-of-N removes. Parsed and preserved, and — since ADR-0008 —
     * ENFORCED by [Membership.evaluate] as rule 5: a member's remove takes effect
     * only with k(N) distinct member signatures (the primary [by] plus valid
     * member cosigs). A cosigner signs [coreBytes] (the payload with `cosig`
     * omitted, byte-identical to a no-cosig op) under [cosigDomain].
     */
    val cosig: List<Cosig>,
    /** Issued-at, unix seconds. */
    val issuedAt: Long,
    /** Expiry (unix seconds) for an add; 0 for a remove, which never expires. */
    val expiresAt: Long,
    /**
     * The body's ADR-0009 `typ` claim as signed: [TokenType.OP], [TokenType.CERT] (a
     * cert read as a genesis add), or `""` for an untyped legacy token. It is carried
     * so that [coreBytes] reproduces the exact signed payload.
     */
    val typ: String = "",
) {
    /** What an op does to the membership set. */
    enum class Kind(val wire: String) {
        ADD("add"),
        REMOVE("remove"),
        ;

        companion object {
            fun fromWire(s: String): Kind? = entries.firstOrNull { it.wire == s }
        }
    }

    /** A co-signature over the op's [coreBytes] by a second member (see [cosig]). */
    data class Cosig(val by: String, val sig: String)

    /** Whether the op is signed by the identity's genesis key. */
    val genesis: Boolean get() = by == user

    /**
     * Why an op is refused by [verify]. Distinct because they call for different
     * actions; [Membership.evaluate] maps them onto its `rejected` reasons.
     */
    enum class Failure { MALFORMED, BAD_SIGNATURE, GENESIS, NO_PREV, WRONG_TYPE }

    /** Thrown by [verify] (and [sign]) for an op that is not an op. */
    class OpException(val failure: Failure, message: String, cause: Throwable? = null) :
        IllegalArgumentException(message, cause)

    // The companion is the op's whole wire API (sign/verify/hash/user plus the
    // ADR-0008 cosig primitives), mirroring void-which-binds-go's enrolment op functions.
    @Suppress("TooManyFunctions")
    companion object {
        /** The version prefixing an op payload; v1 and v2 are certs and are reinterpreted. */
        const val VERSION = 3

        /** Renders an op hash: `sha256:<hex>` over the token's bytes. */
        const val HASH_PREFIX = "sha256:"

        /** Bounds how many heads one op may cite (void-which-binds-go `enrolment.MaxPrev`). */
        const val MAX_PREV = 64

        /** The default add lifetime — 90 days, renewable by any member re-adding. */
        const val DEFAULT_LIFETIME_SECONDS: Long = Enrolment.DEFAULT_LIFETIME_SECONDS

        private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

        /** The id of a token: [HASH_PREFIX] + hex(sha256(token)). */
        fun hash(token: String): String = HASH_PREFIX + Hex.encode(sha256.hashBlocking(token.encodeToByteArray()))

        /**
         * Mint a v3 op signed by [signer] (whose public key is [byPublicKey]) for
         * identity [usr]: an add of [dev] (with its encryption key [deviceEnc], opaque
         * here) valid for [lifetimeSeconds] from [issuedAt] (≤ 0 → the default), or a
         * remove of [dev] (lifetime ignored). [prev] are the signer's current heads
         * ([Membership.View.heads]) — the causal evidence that the signer was a member.
         *
         * A genesis signer (`byPublicKey` renders to [usr]) may cite no prev — the first
         * add, or a recovery re-add — but must cite the remove it overrides for a
         * re-add to be honoured. A member signer must cite at least one head
         * ([Failure.NO_PREV]): an empty past is never a member's.
         *
         * Mirrors void-which-binds-go `enrolment.SignOp` byte-for-byte.
         */
        fun sign(
            signer: Ed25519Signer,
            byPublicKey: ByteArray,
            usr: String,
            kind: Kind,
            dev: String,
            deviceEnc: String,
            prev: List<String>,
            issuedAt: Long,
            lifetimeSeconds: Long = DEFAULT_LIFETIME_SECONDS,
        ): String = signTyped(
            TokenType.OP,
            signer,
            byPublicKey,
            usr,
            kind,
            dev,
            deviceEnc,
            prev,
            issuedAt,
            lifetimeSeconds,
        )

        /**
         * [sign] with an explicit ADR-0009 `typ`. Since phase 2 [sign] passes
         * [TokenType.OP]; `""` mints the untyped legacy body, which only the legacy
         * fixtures still use.
         */
        internal fun signTyped(
            typ: String,
            signer: Ed25519Signer,
            byPublicKey: ByteArray,
            usr: String,
            kind: Kind,
            dev: String,
            deviceEnc: String,
            prev: List<String>,
            issuedAt: Long,
            lifetimeSeconds: Long = DEFAULT_LIFETIME_SECONDS,
        ): String {
            val usrRef = try {
                KeyRef.parse(usr)
            } catch (e: IllegalArgumentException) {
                throw OpException(Failure.MALFORMED, "usr: ${e.message}")
            }
            require(usrRef.alg == Labels.ALG_ED25519 && usrRef.bytes.size == 32) { "usr must be a 32-byte ed25519 key" }
            if (dev.isEmpty()) throw OpException(Failure.MALFORMED, "a device is required")
            if (dev == usr) throw OpException(Failure.GENESIS, "genesis cannot be added or removed")
            if (issuedAt <= 0) throw OpException(Failure.MALFORMED, "an issued-at is required")
            val by = KeyRef.ed25519(byPublicKey).render()
            val heads = normalisePrev(prev)
            if (heads.size > MAX_PREV) throw OpException(Failure.MALFORMED, "${heads.size} prev, max $MAX_PREV")
            if (by != usr &&
                heads.isEmpty()
            ) {
                throw OpException(Failure.NO_PREV, "a member-signed op must cite its heads")
            }

            val fields = ArrayList<Pair<String, Any>>()
            fields += "v" to VERSION
            fields += typFields(typ)
            fields += "usr" to usr
            fields += "op" to kind.wire
            fields += "dev" to dev
            var exp = 0L
            when (kind) {
                Kind.ADD -> {
                    val life = if (lifetimeSeconds <= 0) DEFAULT_LIFETIME_SECONDS else lifetimeSeconds
                    if (deviceEnc.isNotEmpty()) fields += "denc" to deviceEnc
                    exp = issuedAt + life
                }

                Kind.REMOVE -> { /* a remove binds no encryption key and never expires */ }
            }
            fields += "by" to by
            fields += "prev" to heads
            fields += "iat" to issuedAt
            if (exp != 0L) fields += "exp" to exp
            val body = MiniJson.encodeObject(fields).encodeToByteArray()
            return Base64Url.encode(body) + "." + Base64Url.encode(signer.sign(body))
        }

        /**
         * Parse a token and check its signature under its own `by`. Self-contained —
         * no pinned key, no clock — because the trust decision is not made here: the
         * signature only proves WHO said it, and whether that signer was a member at
         * the time is [Membership.evaluate]'s causal question.
         *
         * A v1 or v2 cert is read as the op it is: an add of its device, signed by
         * genesis (`by = usr`), with no prev. Throws [OpException] for anything that is
         * not an op. Mirrors void-which-binds-go `enrolment.VerifyOp`.
         */
        fun verify(rawToken: String, verifier: Ed25519Verifier = Ed25519Engine.verifier()): MembershipOp {
            val token = rawToken.trim()
            val dot = token.indexOf('.')
            if (dot < 0) throw OpException(Failure.MALFORMED, "malformed membership op")
            val body =
                decodeOrNull(token.substring(0, dot))
                    ?: throw OpException(Failure.MALFORMED, "payload is not base64url")
            val sig =
                decodeOrNull(token.substring(dot + 1))
                    ?: throw OpException(Failure.MALFORMED, "signature is not base64url")
            val obj = try {
                MiniJson.parseObject(body.decodeToString())
            } catch (_: Throwable) {
                throw OpException(Failure.MALFORMED, "payload is not JSON")
            }
            // ADR-0009: an op verifier accepts an op or a cert (a genesis add). Any
            // other `typ` is refused before the body is read as either.
            val typ = checkOpTyp(obj)
            val v = (obj["v"] as? Long)?.toInt() ?: throw OpException(Failure.MALFORMED, "no version")
            if (!TokenType.versionOk(typ, v)) throw OpException(Failure.MALFORMED, "$typ at v$v")
            val usr = obj["usr"] as? String ?: ""
            val op: MembershipOp = when {
                v in 1 until VERSION -> {
                    // A cert: genesis add, no prev. Its payload has no op/by/prev fields.
                    val dev = obj["dev"] as? String ?: ""
                    if (usr.isEmpty() || dev.isEmpty()) throw OpException(Failure.MALFORMED, "a binding is empty")
                    MembershipOp(
                        hash = hash(token), token = token, version = v, user = usr,
                        kind = Kind.ADD, device = dev,
                        deviceEnc = obj["denc"] as? String ?: "",
                        by = usr, prev = emptyList(), cosig = emptyList(),
                        issuedAt = obj["iat"] as? Long ?: 0L,
                        expiresAt = obj["exp"] as? Long ?: 0L,
                        typ = typ,
                    )
                }

                v == VERSION -> {
                    val kindWire = obj["op"] as? String ?: ""
                    val prevRaw = obj["prev"]
                    val prev = when (prevRaw) {
                        null, is MiniJson.Null -> emptyList()

                        is List<*> -> prevRaw.map {
                            it as? String
                                ?: throw OpException(Failure.MALFORMED, "prev is not a string list")
                        }

                        else -> throw OpException(Failure.MALFORMED, "prev is not a list")
                    }
                    val cosigRaw = obj["cosig"]
                    val cosig = when (cosigRaw) {
                        null, is MiniJson.Null -> emptyList()

                        is List<*> -> cosigRaw.map { e ->
                            val m =
                                e as? Map<*, *> ?: throw OpException(Failure.MALFORMED, "cosig entry is not an object")
                            Cosig(m["by"] as? String ?: "", m["sig"] as? String ?: "")
                        }

                        else -> throw OpException(Failure.MALFORMED, "cosig is not a list")
                    }
                    MembershipOp(
                        hash = hash(token), token = token, version = v, user = usr,
                        kind = Kind.fromWire(kindWire) ?: throw OpException(Failure.MALFORMED, "op \"$kindWire\""),
                        device = obj["dev"] as? String ?: "",
                        deviceEnc = obj["denc"] as? String ?: "",
                        by = obj["by"] as? String ?: "",
                        prev = normalisePrev(prev),
                        cosig = cosig,
                        issuedAt = obj["iat"] as? Long ?: 0L,
                        expiresAt = obj["exp"] as? Long ?: 0L,
                        typ = typ,
                    )
                }

                else -> throw OpException(Failure.MALFORMED, "unknown op version $v")
            }
            op.validate()
            // The signature is checked under `by` — the claimed signer. That `by` is a
            // member (or genesis) is Evaluate's job; here we only establish that the
            // holder of `by` signed these bytes.
            val byPub = try {
                KeyRef.parse(op.by)
            } catch (_: IllegalArgumentException) {
                null
            }
            if (byPub == null || byPub.alg != Labels.ALG_ED25519 || byPub.bytes.size != 32) {
                throw OpException(Failure.MALFORMED, "by: unreadable key")
            }
            val ok = try {
                verifier.verify(byPub.bytes, body, sig)
            } catch (_: Throwable) {
                false
            }
            if (!ok) throw OpException(Failure.BAD_SIGNATURE, "membership op signature does not verify")
            return op
        }

        /**
         * The identity an op CLAIMS, without verifying it — the hint an RP uses to pick
         * which pinned genesis key to evaluate under (void-which-binds-go `enrolment.OpUser`).
         * Accepts every version [verify] accepts; throws [OpException] otherwise.
         */
        fun user(rawToken: String): String {
            val token = rawToken.trim()
            val dot = token.indexOf('.')
            if (dot < 0) throw OpException(Failure.MALFORMED, "malformed membership op")
            val body =
                decodeOrNull(token.substring(0, dot))
                    ?: throw OpException(Failure.MALFORMED, "payload is not base64url")
            val obj = try {
                MiniJson.parseObject(body.decodeToString())
            } catch (_: Throwable) {
                throw OpException(Failure.MALFORMED, "payload is not JSON")
            }
            val typ = checkOpTyp(obj)
            val v = (obj["v"] as? Long)?.toInt() ?: 0
            val usr = obj["usr"] as? String ?: ""
            val known = v in 1..VERSION && TokenType.versionOk(typ, v)
            if (!known || usr.isEmpty()) throw OpException(Failure.MALFORMED, "malformed membership op")
            return usr
        }

        /** Sort + de-duplicate a prev list so equal head sets sign to equal bytes. */
        fun normalisePrev(prev: List<String>): List<String> =
            prev.map { it.trim() }.filter { it.isNotEmpty() }.distinct().sorted()

        /**
         * Domain tag separating a co-signature's preimage from every other thing an
         * identity key signs (an op body, a possession proof, a pairing SAS): a cosig
         * signs [cosigDomain] ‖ core, never bare bytes replayable as one of those. A
         * simple prefix (not length-framed) per ADR-0008 §A — the trailing NUL is
         * load-bearing and byte-for-byte with void-which-binds-go's `cosigDomain`.
         */
        @Suppress("ktlint:standard:property-naming") // named after Go's cosigDomain; public API
        const val cosigDomain = "voidbind-cosig-v1\u0000"

        /**
         * The bytes a co-signature covers: the op's signed payload with the `cosig`
         * field omitted. Because `cosig` is omitempty this is byte-identical to the
         * payload the op would sign with no cosig at all, so a cosigner signs the same
         * core whether it co-signs alone or beside others, and [Membership.evaluate]
         * can reconstruct the exact preimage from a parsed op. Mirrors void-which-binds-go
         * `enrolment.coreBytes` byte-for-byte (same field order and omitempty rules as
         * [sign]: `typ` second when present (ADR-0009), `denc`/`exp` omitted when
         * empty/zero, `prev` always present). Leaving `typ` out here would make every
         * typed cosigned remove under-threshold, and this replica would then diverge.
         */
        fun coreBytes(op: MembershipOp): ByteArray = payloadBytes(op, emptyList())

        /** The preimage a cosigner signs: [cosigDomain] followed by the op's [core] bytes. */
        fun cosigMessage(core: ByteArray): ByteArray = cosigDomain.encodeToByteArray() + core

        /**
         * [cosigner]'s co-signature over [op]'s core (ADR-0008): the second device's
         * contribution to a k-of-N remove. [op] is the uncosigned remove the primary
         * proposes (as [verify] parsed it); the cosigner signs [cosigMessage] of its
         * [coreBytes]. [cosignerPublicKey] is the cosigner's raw 32-byte Ed25519 public
         * key, rendered into the cosig's `by`. The caller (or a relay) collects these and
         * hands them to [attachCosigs] on the primary's device.
         *
         * The core omits `cosig`, so co-signing an op that already carries cosigs signs
         * the same bytes as co-signing its bare form. Whether the cosig COUNTS is
         * [Membership.evaluate]'s business (rule 5: only members of the op's closure).
         *
         * Mirrors void-which-binds-go `enrolment.CosignOp` byte-for-byte.
         */
        fun cosign(cosigner: Ed25519Signer, cosignerPublicKey: ByteArray, op: MembershipOp): Cosig {
            require(cosignerPublicKey.size == 32) { "a co-signing key is required" }
            val by = KeyRef.ed25519(cosignerPublicKey).render()
            val sig = cosigner.sign(cosigMessage(coreBytes(op)))
            return Cosig(by = by, sig = Base64Url.encode(sig))
        }

        /**
         * Re-mint [op]'s token with [cosigs] attached, signed afresh by the primary
         * ([primary], whose public key [primaryPublicKey] must render to `op.by`, else
         * [Failure.MALFORMED]). Each cosig must already cover op's core (see [cosign]);
         * the primary signature then covers the whole payload, cosigs included. The
         * returned token has a NEW hash, so it — not the uncosigned proposal — is what the
         * primary publishes. Any cosigs already on [op] are replaced by [cosigs], and an
         * empty [cosigs] omits the field (Go's `omitempty`). A bad or foreign cosig is
         * preserved but ignored by [Membership.evaluate], never fatal.
         *
         * Mirrors void-which-binds-go `enrolment.AttachCosigs` byte-for-byte: the payload keeps
         * [op]'s `typ` (so a typed op stays typed and an untyped one untyped), with
         * `cosig` placed between `prev` and `iat`.
         */
        fun attachCosigs(
            primary: Ed25519Signer,
            primaryPublicKey: ByteArray,
            op: MembershipOp,
            cosigs: List<Cosig>,
        ): String {
            require(primaryPublicKey.size == 32) { "a signing key is required" }
            if (KeyRef.ed25519(primaryPublicKey).render() != op.by) {
                throw OpException(Failure.MALFORMED, "primary key is not op.by")
            }
            val body = payloadBytes(op, cosigs)
            return Base64Url.encode(body) + "." + Base64Url.encode(primary.sign(body))
        }

        /**
         * The v3 signed payload of [op] with [cosigs] (omitted when empty) — the one
         * encoder behind [coreBytes] and [attachCosigs], in the field order and
         * omitempty rules of [sign] and void-which-binds-go's `opPayload`.
         */
        private fun payloadBytes(op: MembershipOp, cosigs: List<Cosig>): ByteArray {
            val fields = ArrayList<Pair<String, Any>>()
            fields += "v" to op.version
            fields += typFields(op.typ)
            fields += "usr" to op.user
            fields += "op" to op.kind.wire
            fields += "dev" to op.device
            if (op.deviceEnc.isNotEmpty()) fields += "denc" to op.deviceEnc
            fields += "by" to op.by
            fields += "prev" to op.prev
            if (cosigs.isNotEmpty()) fields += "cosig" to cosigs.map { listOf("by" to it.by, "sig" to it.sig) }
            fields += "iat" to op.issuedAt
            if (op.expiresAt != 0L) fields += "exp" to op.expiresAt
            return MiniJson.encodeObject(fields).encodeToByteArray()
        }

        /** Decode a cosig `sig` (base64url, no padding); null if malformed. */
        internal fun decodeSigOrNull(s: String): ByteArray? = decodeOrNull(s)

        private fun decodeOrNull(s: String): ByteArray? = try {
            if (s.contains('=') || s.contains('+') || s.contains('/')) null else Base64Url.decode(s)
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * The structural check shared by every version once parsed: bindings present,
     * kinds sane, an add has a window that advances, a remove has none, and genesis
     * is never a device. Mirrors Go's `Op.validate`.
     */
    private fun validate() {
        if (user.isEmpty() || device.isEmpty() ||
            by.isEmpty()
        ) {
            throw OpException(Failure.MALFORMED, "a binding is empty")
        }
        val usrRef = try {
            KeyRef.parse(user)
        } catch (e: IllegalArgumentException) {
            throw OpException(Failure.MALFORMED, "usr: ${e.message}")
        }
        if (usrRef.alg != Labels.ALG_ED25519 ||
            usrRef.bytes.size != 32
        ) {
            throw OpException(Failure.MALFORMED, "usr: not an ed25519 key")
        }
        if (device == user) throw OpException(Failure.GENESIS, "genesis cannot be added or removed")
        if (issuedAt <= 0) throw OpException(Failure.MALFORMED, "no issued-at")
        if (prev.size > MAX_PREV) throw OpException(Failure.MALFORMED, "${prev.size} prev, max $MAX_PREV")
        for (h in prev) {
            if (!h.startsWith(HASH_PREFIX) || h.length != HASH_PREFIX.length + 64) {
                throw OpException(Failure.MALFORMED, "prev \"$h\" is not an op hash")
            }
        }
        when (kind) {
            Kind.ADD -> if (expiresAt == 0L || expiresAt <= issuedAt) {
                throw OpException(Failure.MALFORMED, "an add needs an expiry after its issued-at")
            }

            Kind.REMOVE -> {
                if (expiresAt != 0L) throw OpException(Failure.MALFORMED, "a remove does not expire")
                if (deviceEnc.isNotEmpty()) throw OpException(Failure.MALFORMED, "a remove binds no encryption key")
            }
        }
        if (!genesis && prev.isEmpty()) throw OpException(Failure.NO_PREV, "a member-signed op must cite its heads")
    }
}

/** [TokenType.check] for the op verifiers, mapped onto [MembershipOp.OpException]. */
private fun checkOpTyp(obj: Map<String, Any>): String = try {
    TokenType.check(obj, TokenType.OP, TokenType.CERT)
} catch (e: TokenType.TypeException) {
    val f = when (e.failure) {
        TokenType.Failure.WRONG_TYPE -> MembershipOp.Failure.WRONG_TYPE
        TokenType.Failure.MALFORMED -> MembershipOp.Failure.MALFORMED
    }
    throw MembershipOp.OpException(f, e.message ?: "bad typ", e)
}

/** The ADR-0009 `typ` member (second, after `v`), or nothing for an untyped body. */
private fun typFields(typ: String): List<Pair<String, Any>> = if (typ.isEmpty()) emptyList() else listOf("typ" to typ)
