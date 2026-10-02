package one.rarebit.voidwhichbinds.roster

import dev.whyoleg.cryptography.random.CryptographyRandom
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.TokenType
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.roster.RosterException.Failure
import kotlin.random.Random

/**
 * The **org roster** of void-which-binds-go ADR-0014 (and its re-root chain, ADR-0015):
 * a port of void-which-binds-go's `roster` package, byte- and verdict-compatible. An
 * org is a gen2 genesis identity (its id is the founding genesis key) with a roster of
 * persons, kept as a signed op log under the token type [TYP] and evaluated by
 * [evaluate], beside (and separate from) the device-membership evaluator
 * [one.rarebit.voidwhichbinds.Membership.evaluate].
 *
 * A roster op is a sigtoken envelope over a payload minted in exactly this order:
 * ```
 * {v:1, typ:"void-which-binds.roster", org, op, mem?, role?, key?, exp?,
 *  succ?, pick?, by, usr?, bprev?, prev, cosig?, succsig?, iat}
 * ```
 * A signer is a key plus a person: the authority key (`by` alone), a sovereign person's
 * device (`by`, `usr` = the person's genesis key, `bprev` = the person's membership
 * heads), a sovereign person's genesis (`by == usr`), or a managed person's enrolled key
 * (`usr` = `mp:<hex>`). Cosig entries carry the same triple and sign
 * `"void-which-binds-roster-cosig-v1\x00" ‖ core ‖ 0x00 ‖ usr ‖ 0x00 ‖ join(bprev, ",")`,
 * where core is the payload without `cosig` and `succsig` ([RosterDraft.core]).
 * [verify] refuses any body that is not the canonical encoding of what it parses to.
 *
 * The golden vectors in void-which-binds-go's `testvectors/vectors/roster/` are replayed
 * verbatim by `RosterVectorTest`; a divergence there is a bug in this port.
 */
@Suppress("TooManyFunctions")
object Roster {
    /** The ADR-0009 token-type claim of a roster op (ADR-0014). */
    const val TYP = "void-which-binds.roster"

    /** The roster op format version, the payload's `v`. */
    const val VERSION = 1

    /** Renders an op hash: `sha256:` + hex(sha256(token)). */
    const val HASH_PREFIX = MembershipOp.HASH_PREFIX

    /** Bounds `prev` and every `bprev`. */
    const val MAX_PREV = 64

    /** Bounds the cosig entries on one op. */
    const val MAX_COSIGS = 8

    /** Starts an org-managed person id: `mp:` and 32 lowercase hex characters. */
    const val MANAGED_PREFIX = "mp:"

    /** The roster cosig domain (distinct from the person-op cosig domain and the succsig domain). */
    const val COSIG_DOMAIN = "void-which-binds-roster-cosig-v1\u0000"

    /** A re-root's successor-signature domain (ADR-0015). */
    const val SUCC_SIG_DOMAIN = "void-which-binds-roster-reroot-v1\u0000"

    private const val MANAGED_ID_BYTES = 16

    /** The id of a token: [HASH_PREFIX] + hex(sha256(token)). */
    fun opHash(token: String): String = MembershipOp.hash(token)

    /**
     * Make [signer]'s cosig entry on [draft] (ADR-0014, "Cosigs"). [usr] is the person
     * the signer signs for (a sovereign person's genesis key, or a managed person's
     * `mp:` id) and [bprev] that sovereign person's membership heads as the signing
     * device knows them (empty when the signer is the person's genesis or a managed
     * key); bprev is sorted and de-duplicated. Whether the entry COUNTS is [evaluate]'s
     * question. Mirrors Go `roster.CosignWith`.
     */
    @Suppress("LongParameterList")
    fun cosignWith(
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        draft: RosterDraft,
        usr: String,
        bprev: List<String>,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): RosterSignature {
        val by = render(signerPublicKey)
        val nb = RosterWire.normalise(bprev)
        RosterWire.validateSigner(by, usr, nb, primary = false)
        val core = draft.core()
        val sig = signatureWith(signer, signerPublicKey, RosterWire.cosigPreimage(core, usr, nb), verifier)
        return RosterSignature(by = by, usr = usr, bprev = nb, sig = Base64Url.encode(sig))
    }

    /**
     * A re-root's successor signature (ADR-0015): [succ] signs
     * `"void-which-binds-roster-reroot-v1\x00" ‖ core`. Its key must be `draft.succ`.
     * Set the result as [RosterDraft.succSig] before [signWith]. Mirrors Go
     * `roster.SuccSigWith`.
     */
    fun succSigWith(
        succ: Ed25519Signer,
        succPublicKey: ByteArray,
        draft: RosterDraft,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): String {
        if (draft.op != OpKind.REROOT || render(succPublicKey) != draft.succ) {
            throw RosterException(Failure.MALFORMED, "roster: the successor signer is not the reroot's succ")
        }
        val core = draft.copy(succSig = "").core()
        return Base64Url.encode(signatureWith(succ, succPublicKey, RosterWire.succSigPreimage(core), verifier))
    }

    /**
     * Mint the roster op [draft] with [cosigs] attached, signed by [signer] as `by`
     * ([signerPublicKey] must render to `draft.by`). The cosig entries are carried as
     * given (a bad one is preserved and simply does not count). Refuses a draft that
     * [verify] would refuse as malformed, so a minted op always parses. Mirrors Go
     * `roster.SignWith`.
     */
    fun signWith(
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        draft: RosterDraft,
        cosigs: List<RosterSignature>,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): String {
        if (render(signerPublicKey) != draft.by) {
            throw RosterException(Failure.MALFORMED, "roster: the signer is not the draft's by")
        }
        if (draft.iat == 0L) throw RosterException(Failure.MALFORMED, "roster: an issued-at is required")
        val p = draft.payload().copy(cosig = cosigs)
        RosterWire.validate(p)
        if (p.op == OpKind.REROOT.wire) checkSuccSig(p, RosterWire.coreOf(p), verifier)
        val body = RosterWire.encode(p)
        val sig = signatureWith(signer, signerPublicKey, body, verifier)
        return Base64Url.encode(body) + "." + Base64Url.encode(sig)
    }

    /**
     * Parse [rawToken] as a roster op and check it as far as the op alone allows: the
     * `typ` ([Failure.WRONG_TYPE]), canonical encoding and every field rule
     * ([Failure.MALFORMED]), a re-root's successor signature ([Failure.MALFORMED]), and
     * the primary signature under `by` ([Failure.BAD_SIGNATURE]). It does not judge
     * cosigs, `prev`, `bprev` or authority. Mirrors Go `roster.Verify`.
     */
    @Suppress("ThrowsCount")
    fun verify(rawToken: String, verifier: Ed25519Verifier = Ed25519Engine.verifier()): RosterOp {
        val token = rawToken.trim()
        val dot = token.indexOf('.')
        if (dot < 0) throw RosterException(Failure.MALFORMED, "roster: malformed roster op")
        val body = RosterWire.decodeRaw(token.substring(0, dot))
        val sig = RosterWire.decodeRaw(token.substring(dot + 1))
        if (body == null || sig == null) throw RosterException(Failure.MALFORMED, "roster: malformed roster op")
        val obj = try {
            MiniJson.parseObject(body.decodeToString())
        } catch (e: IllegalArgumentException) {
            throw RosterException(Failure.MALFORMED, "roster: malformed roster op: not JSON", e)
        }
        try {
            TokenType.check(obj, TYP)
        } catch (e: TokenType.TypeException) {
            val f = if (e.failure == TokenType.Failure.WRONG_TYPE) Failure.WRONG_TYPE else Failure.MALFORMED
            throw RosterException(f, "roster: ${e.message}", e)
        }
        // Deterministic minting is part of the contract (ADR-0009): a body that is not
        // exactly the canonical encoding of what it parses to is refused.
        val p = try {
            require(!RosterWire.containsNull(obj)) { "null member" }
            RosterWire.parse(obj)
        } catch (e: IllegalArgumentException) {
            throw RosterException(Failure.MALFORMED, "roster: malformed roster op: ${e.message}", e)
        }
        if (!RosterWire.encode(p).contentEquals(body)) {
            throw RosterException(Failure.MALFORMED, "roster: malformed roster op: not the canonical encoding")
        }
        RosterWire.validate(p)
        val core = RosterWire.coreOf(p)
        if (p.op == OpKind.REROOT.wire) checkSuccSig(p, core, verifier)
        val byPub = RosterWire.edKeyOrNull(p.by)!!
        if (!safeVerify(verifier, byPub, body, sig)) {
            throw RosterException(Failure.BAD_SIGNATURE, "roster: roster op signature does not verify")
        }
        return RosterOp(
            hash = opHash(token), token = token, org = p.org, kind = OpKind.fromWire(p.op)!!, mem = p.mem,
            role = p.role, key = p.key, exp = p.exp, succ = p.succ, pick = p.pick, by = p.by, usr = p.usr,
            bprev = p.bprev, prev = p.prev, cosig = p.cosig, succSig = p.succSig, iat = p.iat,
        )
    }

    /** Whether [s] signed [op]'s cosig preimage under `s.by`. It says nothing about whether s counts. */
    @Suppress("ReturnCount")
    fun verifyCosig(op: RosterOp, s: RosterSignature, verifier: Ed25519Verifier = Ed25519Engine.verifier()): Boolean {
        val pub = RosterWire.edKeyOrNull(s.by) ?: return false
        val sig = RosterWire.decodeRaw(s.sig) ?: return false
        return safeVerify(verifier, pub, RosterWire.cosigPreimage(op.core, s.usr, s.bprev), sig)
    }

    /** A fresh org-managed person id: `mp:` and 16 random bytes as lowercase hex. */
    fun newManagedId(random: Random = CryptographyRandom.Default): String =
        MANAGED_PREFIX + Hex.encode(random.nextBytes(MANAGED_ID_BYTES))

    /**
     * The CRDT join over roster op tokens: the union (trimmed, empties dropped),
     * de-duplicated by hash and returned in hash order. It does not verify; [evaluate]
     * does. Mirrors Go `roster.Merge`.
     */
    fun merge(vararg sets: List<String>): List<String> {
        val byHash = HashMap<String, String>()
        for (set in sets) {
            for (raw in set) {
                val tok = raw.trim()
                if (tok.isNotEmpty()) byHash[opHash(tok)] = tok
            }
        }
        return byHash.keys.sorted().map { byHash.getValue(it) }
    }

    /**
     * Compute [org]'s roster over the op tokens [ops] at [now] (unix seconds), ADR-0014
     * and ADR-0015. [founding] is the founding op token the relying party pinned beside
     * the org id (it is merged into ops). [persons] returns the person-op tokens the
     * evaluator holds for a sovereign person (their recorded log merged with any
     * presented ops), and may be null. Throws [RosterException] ([Failure.NO_ORG],
     * [Failure.FOUNDING]) or [IllegalArgumentException] for a missing clock; every
     * problem with an individual op is reported in the [RosterView]. Mirrors Go
     * `roster.Evaluate`.
     */
    @Suppress("ComplexCondition", "LongParameterList", "ThrowsCount")
    fun evaluate(
        org: String,
        founding: String,
        ops: List<String>,
        persons: ((String) -> List<String>)?,
        now: Long,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): RosterView {
        if (!RosterWire.isEdKey(org)) {
            throw RosterException(Failure.NO_ORG, "roster: the org id must be an Ed25519 key")
        }
        require(now != 0L) { "roster: a clock is required" }
        val f = try {
            verify(founding, verifier)
        } catch (e: RosterException) {
            throw RosterException(Failure.FOUNDING, "roster: not a founding op of this org: ${e.message}", e)
        }
        if (f.org != org || f.by != org || f.usr.isNotEmpty() || f.kind != OpKind.SET || f.role != Role.OWNER ||
            f.prev.isNotEmpty()
        ) {
            throw RosterException(Failure.FOUNDING, "roster: not a founding op of this org")
        }
        val e = RosterEvaluator(org, persons, verifier)
        e.founding = opHash(founding.trim())
        e.ingest(listOf(founding) + ops)
        e.resolve()
        return e.view(now)
    }

    private fun render(publicKey: ByteArray): String {
        require(publicKey.size == ED25519_KEY_LEN) { "roster: the signer is not an Ed25519 key" }
        return KeyRef.ed25519(publicKey).render()
    }

    /**
     * Go `sigtoken.SignatureWith`: sign through the seam, then refuse a signature that
     * does not verify under the signer's public key (a custody signer that answered with
     * another key's signature).
     */
    private fun signatureWith(
        signer: Ed25519Signer,
        publicKey: ByteArray,
        msg: ByteArray,
        verifier: Ed25519Verifier,
    ): ByteArray {
        val sig = signer.sign(msg)
        check(sig.size == SIGNATURE_LEN && safeVerify(verifier, publicKey, msg, sig)) {
            "roster: signing: the signer returned a signature that does not verify under its public key"
        }
        return sig
    }

    /** A re-root's successor signature over its core (validate has checked succ is an Ed25519 key). */
    private fun checkSuccSig(p: RosterWire.Payload, core: ByteArray, verifier: Ed25519Verifier) {
        val succ = RosterWire.edKeyOrNull(p.succ)
            ?: throw RosterException(Failure.MALFORMED, "roster: malformed roster op: succ")
        val ss = RosterWire.decodeRaw(p.succSig)
        if (ss == null || p.succSig.isEmpty() || !safeVerify(verifier, succ, RosterWire.succSigPreimage(core), ss)) {
            throw RosterException(Failure.MALFORMED, "roster: malformed roster op: succsig does not verify")
        }
    }

    internal fun safeVerify(verifier: Ed25519Verifier, pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = try {
        verifier.verify(pub, msg, sig)
    } catch (_: Exception) {
        false
    }

    private const val ED25519_KEY_LEN = 32
    private const val SIGNATURE_LEN = 64
}
