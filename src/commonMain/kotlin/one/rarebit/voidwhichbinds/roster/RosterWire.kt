package one.rarebit.voidwhichbinds.roster

import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.roster.RosterException.Failure

/**
 * The roster op's encoding and op-local rules: a byte-for-byte port of the private
 * half of void-which-binds-go `roster/op.go` (`payload`, `coreOf`, the preimages,
 * `validate`, `validateSigner`, `checkHashes`, …).
 */
@Suppress("TooManyFunctions")
internal object RosterWire {

    /** Ed25519 signature length. */
    private const val SIGNATURE_SIZE = 64

    /** Hex characters in an op hash's digest. */
    private const val HASH_HEX = 64

    /** Hex characters in a managed id (16 bytes). */
    private const val MANAGED_HEX = 32

    /**
     * The signed body. Its field order is the minting order ADR-0014 fixes ([encode]),
     * and [Roster.verify] refuses a body that is not exactly its encoding. Mirrors Go's
     * `payload` struct, `omitempty` included.
     */
    data class Payload(
        val v: Long,
        val typ: String,
        val org: String,
        val op: String,
        val mem: String,
        val role: String,
        val key: String,
        val exp: Long,
        val succ: String,
        val pick: String,
        val by: String,
        val usr: String,
        val bprev: List<String>,
        val prev: List<String>,
        val cosig: List<RosterSignature>,
        val succSig: String,
        val iat: Long,
    )

    /** Go's `json.Marshal(payload)`: compact, in field order, `omitempty` honoured. */
    fun encode(p: Payload): ByteArray {
        val f = ArrayList<Pair<String, Any>>()
        f += "v" to p.v
        f += "typ" to p.typ
        f += "org" to p.org
        f += "op" to p.op
        if (p.mem.isNotEmpty()) f += "mem" to p.mem
        if (p.role.isNotEmpty()) f += "role" to p.role
        if (p.key.isNotEmpty()) f += "key" to p.key
        if (p.exp != 0L) f += "exp" to p.exp
        if (p.succ.isNotEmpty()) f += "succ" to p.succ
        if (p.pick.isNotEmpty()) f += "pick" to p.pick
        f += "by" to p.by
        if (p.usr.isNotEmpty()) f += "usr" to p.usr
        if (p.bprev.isNotEmpty()) f += "bprev" to p.bprev
        f += "prev" to p.prev
        if (p.cosig.isNotEmpty()) f += "cosig" to p.cosig.map(::signatureFields)
        if (p.succSig.isNotEmpty()) f += "succsig" to p.succSig
        f += "iat" to p.iat
        return MiniJson.encodeObject(f).encodeToByteArray()
    }

    private fun signatureFields(s: RosterSignature): List<Pair<String, Any>> {
        val f = ArrayList<Pair<String, Any>>()
        f += "by" to s.by
        if (s.usr.isNotEmpty()) f += "usr" to s.usr
        if (s.bprev.isNotEmpty()) f += "bprev" to s.bprev
        f += "sig" to s.sig
        return f
    }

    /** The core: the payload marshalled with `cosig` and `succsig` omitted (Go `coreOf`). */
    fun coreOf(p: Payload): ByteArray = encode(p.copy(cosig = emptyList(), succSig = ""))

    /** `"void-which-binds-roster-cosig-v1\x00" ‖ core ‖ 0x00 ‖ usr ‖ 0x00 ‖ join(bprev, ",")`. */
    fun cosigPreimage(core: ByteArray, usr: String, bprev: List<String>): ByteArray =
        Roster.COSIG_DOMAIN.encodeToByteArray() + core + byteArrayOf(0) + usr.encodeToByteArray() +
            byteArrayOf(0) + bprev.joinToString(",").encodeToByteArray()

    /** `"void-which-binds-roster-reroot-v1\x00" ‖ core`. */
    fun succSigPreimage(core: ByteArray): ByteArray = Roster.SUCC_SIG_DOMAIN.encodeToByteArray() + core

    /**
     * Go's `base64.RawURLEncoding.DecodeString`: URL alphabet, no padding, and (as Go's
     * decoder does) `\r` and `\n` skipped. Null if it does not decode.
     */
    fun decodeRaw(s: String): ByteArray? {
        val t = if (s.contains('\r') || s.contains('\n')) s.filter { it != '\r' && it != '\n' } else s
        return try {
            if (t.contains('=') || t.contains('+') || t.contains('/')) null else Base64Url.decode(t)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /**
     * Parse [body] into a [Payload] the way Go's `json.Unmarshal` into the struct would
     * succeed, or throw. Values of the wrong JSON type are refused; a JSON `null` (which
     * no canonical body carries) is refused outright, and unknown members are dropped
     * (the canonical re-encoding then differs from the body, as in Go).
     */
    @Suppress("CyclomaticComplexMethod")
    fun parse(obj: Map<String, Any>): Payload {
        fun str(k: String): String = when (val x = obj[k]) {
            null -> ""
            is String -> x
            else -> throw IllegalArgumentException("$k is not a string")
        }

        fun num(k: String): Long = when (val x = obj[k]) {
            null -> 0L
            is Long -> x
            else -> throw IllegalArgumentException("$k is not an integer")
        }

        fun strList(x: Any?, k: String): List<String> = when (x) {
            null -> emptyList()
            is List<*> -> x.map { it as? String ?: throw IllegalArgumentException("$k is not a string list") }
            else -> throw IllegalArgumentException("$k is not a list")
        }
        val cosig = when (val x = obj["cosig"]) {
            null -> emptyList()

            is List<*> -> x.map { e ->
                val m = e as? Map<*, *> ?: throw IllegalArgumentException("cosig entry is not an object")
                fun s(k: String): String = when (val y = m[k]) {
                    null -> ""
                    is String -> y
                    else -> throw IllegalArgumentException("cosig $k is not a string")
                }
                RosterSignature(by = s("by"), usr = s("usr"), bprev = strList(m["bprev"], "bprev"), sig = s("sig"))
            }

            else -> throw IllegalArgumentException("cosig is not a list")
        }
        return Payload(
            v = num("v"), typ = str("typ"), org = str("org"), op = str("op"), mem = str("mem"), role = str("role"),
            key = str("key"), exp = num("exp"), succ = str("succ"), pick = str("pick"), by = str("by"),
            usr = str("usr"), bprev = strList(obj["bprev"], "bprev"), prev = strList(obj["prev"], "prev"),
            cosig = cosig, succSig = str("succsig"), iat = num("iat"),
        )
    }

    /** True if the parsed JSON holds a `null` anywhere (no canonical body does). */
    fun containsNull(x: Any?): Boolean = when (x) {
        is MiniJson.Null -> true
        is Map<*, *> -> x.values.any(::containsNull)
        is List<*> -> x.any(::containsNull)
        else -> false
    }

    private fun bad(msg: String): Nothing =
        throw RosterException(Failure.MALFORMED, "roster: malformed roster op: $msg")

    /**
     * Every rule an op can be held to on its own (ADR-0014 rule 1, less prev/bprev
     * resolution and the set-dependent rules). Throws [RosterException]. Mirrors Go's
     * `validate` (which joins every failure; one is enough to refuse).
     */
    @Suppress("CyclomaticComplexMethod", "LongMethod", "ThrowsCount", "NestedBlockDepth", "ComplexCondition")
    fun validate(p: Payload) {
        if (p.v != Roster.VERSION.toLong()) bad("version ${p.v}")
        if (p.typ != Roster.TYP) throw RosterException(Failure.WRONG_TYPE, "roster: token type does not match")
        if (!isEdKey(p.org)) bad("org")
        if (p.iat <= 0) bad("no issued-at")
        checkHashes(p.prev, "prev")
        validateSigner(p.by, p.usr, p.bprev, primary = true)
        // The org is never a person: it signs only in the authority shape, and is never a signature's usr.
        if (p.usr.isNotEmpty() && (p.by == p.org || p.usr == p.org)) bad("the org key signs only as the authority")
        for (c in p.cosig) {
            if (c.by == p.org || c.usr == p.org) bad("the org key signs only as the authority")
        }
        if (p.by != p.org && p.prev.isEmpty()) bad("a non-authority op must cite its heads")
        if (p.cosig.size > Roster.MAX_COSIGS) bad("${p.cosig.size} cosig entries, max ${Roster.MAX_COSIGS}")
        for (c in p.cosig) {
            validateSigner(c.by, c.usr, c.bprev, primary = false)
            val sig = decodeRaw(c.sig)
            if (sig == null || sig.size != SIGNATURE_SIZE) bad("cosig entry signature")
        }
        fun has(name: String, set: Boolean) {
            if (!set) bad("op ${p.op} needs $name")
        }
        fun not(name: String, set: Boolean) {
            if (set) bad("op ${p.op} does not take $name")
        }
        if (p.exp != 0L && p.exp <= p.iat) bad("exp is not after iat")
        when (OpKind.fromWire(p.op)) {
            OpKind.SET -> {
                has("mem", p.mem.isNotEmpty())
                has("role", p.role.isNotEmpty())
                not("key", p.key.isNotEmpty())
                if (p.role.isNotEmpty() && Role.rank(p.role) == 0) bad("role \"${p.role}\"")
            }

            OpKind.REMOVE -> {
                has("mem", p.mem.isNotEmpty())
                not("role", p.role.isNotEmpty())
                not("key", p.key.isNotEmpty())
                not("exp", p.exp != 0L)
            }

            OpKind.ENROL, OpKind.UNENROL -> {
                has("mem", p.mem.isNotEmpty())
                not("role", p.role.isNotEmpty())
                has("key", p.key.isNotEmpty())
                if (p.op == OpKind.UNENROL.wire) not("exp", p.exp != 0L)
                if (p.mem.isNotEmpty() &&
                    !p.mem.startsWith(Roster.MANAGED_PREFIX)
                ) {
                    bad("op ${p.op} needs a managed mem")
                }
                if (p.key.isNotEmpty() && !validMemberKey(p.key)) bad("key \"${p.key}\"")
            }

            OpKind.RESET, OpKind.REROOT, OpKind.RESOLVE -> {
                not("mem", p.mem.isNotEmpty())
                not("role", p.role.isNotEmpty())
                not("key", p.key.isNotEmpty())
                not("exp", p.exp != 0L)
            }

            null -> bad("op \"${p.op}\"")
        }
        if (p.op == OpKind.REROOT.wire) {
            has("succ", p.succ.isNotEmpty())
            if (p.succ.isNotEmpty()) {
                when {
                    !isEdKey(p.succ) -> bad("succ")
                    p.succ == p.org -> bad("succ is the org")
                    p.succ == p.by -> bad("succ is the re-root's own signer")
                }
            }
        } else {
            not("succ", p.succ.isNotEmpty())
            not("succsig", p.succSig.isNotEmpty())
        }
        if (p.op == OpKind.RESOLVE.wire) {
            has("pick", p.pick.isNotEmpty())
            if (p.pick.isNotEmpty() && !isHash(p.pick)) bad("pick is not an op hash")
        } else {
            not("pick", p.pick.isNotEmpty())
        }
        if (p.mem.isNotEmpty()) {
            when {
                p.mem == p.org -> bad("mem is the org")

                p.mem.startsWith(Roster.MANAGED_PREFIX) -> {
                    if (!validManagedId(p.mem)) bad("mem \"${p.mem}\"")
                }

                !isEdKey(p.mem) -> bad("mem")
            }
        }
    }

    /**
     * One signer triple's shape. A primary may have no person (the authority shape); a
     * cosig entry always names one.
     */
    fun validateSigner(by: String, usr: String, bprev: List<String>, primary: Boolean) {
        if (!isEdKey(by)) bad("by must be an Ed25519 key")
        checkHashes(bprev, "bprev")
        when {
            usr.isEmpty() -> {
                if (!primary) bad("a cosig entry names no usr")
                if (bprev.isNotEmpty()) bad("bprev without usr")
            }

            usr.startsWith(Roster.MANAGED_PREFIX) -> {
                if (!validManagedId(usr)) bad("usr \"$usr\"")
                if (bprev.isNotEmpty()) bad("a managed person's signature carries no bprev")
            }

            else -> {
                if (!isEdKey(usr)) bad("usr")
                if (by == usr && bprev.isNotEmpty()) bad("a person genesis signature carries no bprev")
            }
        }
    }

    /** A hash list must be sorted, unique, op hashes and within [Roster.MAX_PREV]. */
    fun checkHashes(hs: List<String>, field: String) {
        if (hs.size > Roster.MAX_PREV) bad("${hs.size} $field, max ${Roster.MAX_PREV}")
        for ((i, h) in hs.withIndex()) {
            if (!isHash(h)) bad("$field \"$h\" is not an op hash")
            if (i > 0 && hs[i - 1] >= h) bad("$field is not sorted and unique")
        }
    }

    fun isHash(h: String): Boolean =
        h.startsWith(Roster.HASH_PREFIX) && h.length == Roster.HASH_PREFIX.length + HASH_HEX &&
            isLowerHex(h.substring(Roster.HASH_PREFIX.length))

    private fun isLowerHex(s: String): Boolean = s.all { it in '0'..'9' || it in 'a'..'f' }

    fun validManagedId(s: String): Boolean {
        if (!s.startsWith(Roster.MANAGED_PREFIX)) return false
        val h = s.substring(Roster.MANAGED_PREFIX.length)
        return h.length == MANAGED_HEX && isLowerHex(h)
    }

    /**
     * Whether [s] is an Ed25519 key in its one canonical rendering (Go `edKey`,
     * `identity.ParseCanonicalPublicKey`): two renderings of one key must never count
     * as two persons toward a quorum.
     */
    fun isEdKey(s: String): Boolean = edKeyOrNull(s) != null

    fun edKeyOrNull(s: String): ByteArray? = try {
        KeyRef.parseCanonicalEd25519(s)
    } catch (_: IllegalArgumentException) {
        null
    }

    /**
     * Whether [key] may be enrolled: an Ed25519 key, or an ADR-0018 passkey
     * (`webauthn:es256:` on P-256), in either case canonical — the same rule as a
     * membership op's `dev` ([MembershipOp.checkMemberKey], Go `identity.ParseMemberKey`).
     */
    fun validMemberKey(key: String): Boolean = try {
        MembershipOp.checkMemberKey(key)
        true
    } catch (_: MembershipOp.OpException) {
        false
    }

    /** Whether an enrolled key can sign roster ops: only an Ed25519 key can (a passkey is live but inert here). */
    fun canSign(key: String): Boolean = isEdKey(key)

    /** Trim, drop empties, de-duplicate and sort (Go `normalise`). */
    fun normalise(hs: List<String>): List<String> = hs.map { it.trim() }.filter { it.isNotEmpty() }.distinct().sorted()
}
