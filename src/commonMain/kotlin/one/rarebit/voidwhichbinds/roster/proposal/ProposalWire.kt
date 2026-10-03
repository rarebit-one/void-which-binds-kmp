package one.rarebit.voidwhichbinds.roster.proposal

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.GoJson
import one.rarebit.voidwhichbinds.crypto.GoStrings
import one.rarebit.voidwhichbinds.roster.Roster
import one.rarebit.voidwhichbinds.roster.RosterDraft
import one.rarebit.voidwhichbinds.roster.RosterException
import one.rarebit.voidwhichbinds.roster.RosterOp
import one.rarebit.voidwhichbinds.roster.RosterSignature
import one.rarebit.voidwhichbinds.roster.RosterWire
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.BAD_CORE
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.BAD_VERSION
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.MALFORMED
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.RESTATEMENT_MISMATCH
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.TOO_LARGE

/**
 * The roster **cosign transport** of void-which-binds-go ADR-0014 ("Proposal
 * transport", specified by Phase 3 G4): the byte encoding of the two relay slots a
 * roster op's cosigning rides on, and the checks either side runs on what it receives.
 * A port of void-which-binds-go's `roster/proposal` package, byte- and
 * verdict-compatible; the golden vectors in `vectors/roster-proposal/` are replayed by
 * `RosterProposalVectorTest`.
 *
 * The proposing device opens one relay session per cosigner
 * ([one.rarebit.voidwhichbinds.net.RelayClient.COSIGN_TYPES]) and writes a [Proposal]
 * to the `proposal` slot as the initiator; the cosigner fetches it, runs [check], shows
 * the decoded op to its human, and writes back a [Cosig] ([Checked.cosign]) to the
 * `cosig` slot as the responder; the proposer runs [Checked.verifyCosig] on each and
 * [Checked.assemble] mints the op.
 *
 * Both payloads are canonical JSON (exactly Go's encoding of the parsed value, in this
 * member order, with no insignificant whitespace):
 * ```
 * proposal {"v":1,"slot":"proposal","core":b64url(core),"usr"?,"bprev"?:[opHash…],
 *           "roster":[token…],"persons":{usr:[token…]}}
 * cosig    {"v":1,"slot":"cosig","entry":{"by","usr","bprev"?,"sig"},
 *           "persons":{usr:[token…]}}
 * ```
 * Every token list is in op-hash order without duplicates, every person list is
 * non-empty, and an empty attachment is `[]` / `{}`, never absent or null. Nothing in
 * either slot is trusted: a hostile relay can only withhold.
 */
@Suppress("TooManyFunctions")
object RosterProposal {
    /** The slot payload format version, both slots' `v`. */
    const val VERSION = 1

    /** The proposer's relay slot (and that payload's `slot` member). */
    const val SLOT_PROPOSAL = "proposal"

    /** The cosigner's relay slot (and that payload's `slot` member). */
    const val SLOT_COSIG = "cosig"

    /** Bounds an encoded proposal (512 KiB). Every cap is checked before any token is parsed. */
    const val MAX_PROPOSAL_BYTES = 512 shl 10

    /** Bounds an encoded cosig (128 KiB). */
    const val MAX_COSIG_BYTES = 128 shl 10

    /** Bounds a proposal's `roster` list. */
    const val MAX_ROSTER_OPS = 256

    /** Bounds the persons (keys of `persons`) a proposal carries. */
    const val MAX_PERSONS = 64

    /** Bounds a proposal's person-op tokens, over every person. */
    const val MAX_PERSON_OPS = 256

    /** Bounds a cosig's person-op tokens (one person). */
    const val MAX_COSIG_PERSON_OPS = 128

    /**
     * Build a proposal for [d] with the given attachments (normally [context]'s output).
     * Refuses a draft [RosterDraft.core] refuses ([ProposalReason.BAD_CORE]) and
     * attachments over the caps ([ProposalReason.TOO_LARGE]). Attachments are
     * de-duplicated and put in op-hash order; whether they suffice is [check]'s question.
     * Mirrors Go `proposal.New`.
     */
    @Throws(Exception::class)
    fun create(d: RosterDraft, roster: List<String>, persons: Map<String, List<String>>): Proposal {
        val core = try {
            d.core()
        } catch (e: RosterException) {
            refuse(BAD_CORE, e.message.orEmpty(), e)
        }
        val parsed = try {
            Roster.parseCore(core)
        } catch (e: RosterException) {
            refuse(BAD_CORE, e.message.orEmpty(), e)
        }
        val ps = LinkedHashMap<String, List<String>>()
        for ((usr, list) in persons) {
            val l = byHash(list)
            if (l.isNotEmpty()) ps[usr] = l
        }
        return Proposal(core, parsed, byHash(roster), ps).also { it.encode() }
    }

    /**
     * Parse a `proposal` slot payload, in this order: the byte cap (too_large); the JSON
     * header and its `v` (malformed, bad_version) and `slot` (malformed); the count caps
     * (too_large); the canonical encoding and list forms (malformed); the core (bad_core);
     * and the restated usr and bprev (restatement_mismatch). It checks nothing against an
     * org or a roster: that is [check]. Mirrors Go `proposal.Decode`.
     */
    @Throws(Exception::class)
    fun decode(raw: ByteArray): Proposal {
        val tree = SlotCodec.readHeader(raw, MAX_PROPOSAL_BYTES, SLOT_PROPOSAL)
        val w = SlotCodec.proposalWire(tree)
        proposalCounts(w)
        SlotCodec.canonical(raw, w)
        proposalLists(w)
        val core = RosterWire.decodeRaw(w.core)
        if (core == null || Base64Url.encode(core) != w.core) refuse(BAD_CORE, "core is not canonical base64url")
        val d = try {
            Roster.parseCore(core)
        } catch (e: RosterException) {
            refuse(BAD_CORE, e.message.orEmpty(), e)
        }
        if (w.usr != d.usr || w.bprev.orEmpty().joinToString(",") != d.bprev.joinToString(",")) {
            refuse(RESTATEMENT_MISMATCH, "the restated usr/bprev differ from the core's")
        }
        return Proposal(core, d, w.roster!!, w.persons!!.mapValues { it.value.orEmpty() })
    }

    /**
     * Parse a `cosig` slot payload: the byte cap, the header, version and slot, the count
     * caps (at most one person), and the canonical encoding, in [decode]'s order. The
     * entry's shape and signature are [Checked.verifyCosig]'s. Mirrors Go
     * `proposal.DecodeCosig`.
     */
    @Throws(Exception::class)
    fun decodeCosig(raw: ByteArray): Cosig {
        val tree = SlotCodec.readHeader(raw, MAX_COSIG_BYTES, SLOT_COSIG)
        val w = SlotCodec.cosigWire(tree)
        cosigCounts(w.persons)
        SlotCodec.canonical(raw, w)
        personLists(w.persons!!)
        val e = w.entry
        return Cosig(
            RosterSignature(by = e.by, usr = e.usr, bprev = e.bprev.orEmpty(), sig = e.sig),
            w.persons!!.mapValues { it.value.orEmpty() },
        )
    }

    /**
     * Decode and validate a proposal as a cosigner does before it shows the op to its
     * human; see [Checked] for the order of the checks after [decode]'s. Throws
     * [ProposalException] for a refusal; any other exception is the caller's (an org that
     * is not a key, a founding op that is not the org's). Mirrors Go `proposal.Check`.
     */
    @Throws(Exception::class)
    fun check(raw: ByteArray, expect: Expect, verifier: Ed25519Verifier = Ed25519Engine.verifier()): Checked =
        Checked.of(decode(raw), expect, verifier)

    /**
     * Compute the attachments for a proposal of [d] from the proposer's replica: the
     * roster ops in the closure of d's prev ([founding] included) and, for every sovereign
     * signature with bprev on them and the proposer's own, the closure of that bprev in
     * the person's log. A prev that does not resolve is missing_roster_context, a bprev
     * that does not is missing_person_context. Pass the result to [create]; if it is over
     * the caps, attach only what the cosigner lacks. Mirrors Go `proposal.Context`.
     */
    @Throws(Exception::class)
    fun context(
        d: RosterDraft,
        founding: String,
        ops: List<String>,
        persons: ((String) -> List<String>)?,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): ProposalContext {
        val byHashOps = HashMap<String, RosterOp>()
        for (tok in listOf(founding) + ops) {
            val o = Closures.verifyRoster(tok, verifier)
            if (o != null && o.org == d.org) byHashOps[o.hash] = o
        }
        val closure = Closures.roster(byHashOps, d.prev)
        // Go adds the founding op's hash even when it is not the org's; it then names no
        // op and contributes nothing, so only an op of the org is added here.
        Closures.verifyRoster(founding, verifier)?.let { if (byHashOps.containsKey(it.hash)) closure.add(it.hash) }
        val cops = closure.map { byHashOps.getValue(it) }
        val out = LinkedHashMap<String, List<String>>()
        for ((usr, need) in Closures.personHeads(cops, Closures.Sig(d.usr, d.bprev))) {
            val (inn, ok) = Closures.person(usr, need, persons?.invoke(usr).orEmpty(), verifier)
            if (!ok) refuse(ProposalReason.MISSING_PERSON_CONTEXT, usr)
            out[usr] = byHash(inn.values)
        }
        return ProposalContext(byHash(cops.map { it.token }), out)
    }

    // --- caps and list forms ----------------------------------------------------------

    internal fun proposalCounts(w: SlotCodec.ProposalWire) {
        val r = w.roster.orEmpty().size
        if (r > MAX_ROSTER_OPS) refuse(TOO_LARGE, "$r roster ops, max $MAX_ROSTER_OPS")
        val ps = w.persons.orEmpty()
        if (ps.size > MAX_PERSONS) refuse(TOO_LARGE, "${ps.size} persons, max $MAX_PERSONS")
        val n = ps.values.sumOf { it.orEmpty().size }
        if (n > MAX_PERSON_OPS) refuse(TOO_LARGE, "$n person ops, max $MAX_PERSON_OPS")
    }

    internal fun cosigCounts(persons: Map<String, List<String>?>?) {
        val ps = persons.orEmpty()
        if (ps.size > 1) refuse(TOO_LARGE, "a cosig carries one person's context")
        for (l in ps.values) {
            val n = l.orEmpty().size
            if (n > MAX_COSIG_PERSON_OPS) refuse(TOO_LARGE, "$n person ops, max $MAX_COSIG_PERSON_OPS")
        }
    }

    internal fun proposalLists(w: SlotCodec.ProposalWire) {
        if (!inHashOrder(w.roster.orEmpty())) refuse(MALFORMED, "roster is not in op-hash order without duplicates")
        personLists(w.persons.orEmpty())
    }

    internal fun personLists(persons: Map<String, List<String>?>) {
        for ((usr, l) in persons) {
            if (!RosterWire.isEdKey(usr)) refuse(MALFORMED, "person \"$usr\" is not a sovereign person's key")
            if (l.isNullOrEmpty()) refuse(MALFORMED, "an empty person list")
            if (!inHashOrder(l)) refuse(MALFORMED, "person ops are not in op-hash order without duplicates")
        }
    }

    /**
     * Whether [toks] are non-empty tokens in strictly increasing op-hash order (so no
     * duplicates). A person op's hash is the same construction as a roster op's.
     */
    @Suppress("ReturnCount")
    private fun inHashOrder(toks: List<String>): Boolean {
        var prev = ""
        for (t in toks) {
            if (t.isEmpty() || goTrim(t) != t) return false
            val h = Roster.opHash(t)
            if (h <= prev) return false
            prev = h
        }
        return true
    }

    /** De-duplicate [toks] (trimmed, empties dropped) into op-hash order (Go `byHash`). */
    internal fun byHash(toks: Collection<String>): List<String> {
        val m = HashMap<String, String>()
        for (raw in toks) {
            val t = goTrim(raw)
            if (t.isNotEmpty()) m[Roster.opHash(t)] = t
        }
        return m.keys.sorted().map { m.getValue(it) }
    }

    /** Go's `strings.TrimSpace`, whose whitespace (`unicode.IsSpace`) differs from Kotlin's `trim()`. */
    internal fun goTrim(s: String): String = GoStrings.trimSpace(s)
}

/**
 * The `proposal` slot: a roster op's [core], its proposer's usr and bprev restated (from
 * [draft]), and the attached context. Mirrors Go `proposal.Proposal`.
 */
class Proposal internal constructor(
    /** The bytes every cosig covers ([RosterDraft.core]). */
    val core: ByteArray,
    /** [core] parsed ([Roster.parseCore]); its succSig is empty. */
    val draft: RosterDraft,
    /** The attached roster op tokens, in op-hash order. */
    val roster: List<String>,
    /** The attached person-op tokens by sovereign person, each list in op-hash order. */
    val persons: Map<String, List<String>>,
) {
    /**
     * Render this proposal as its slot payload. Refuses one over the caps
     * ([ProposalReason.TOO_LARGE]) or with lists out of canonical form
     * ([ProposalReason.MALFORMED]). Mirrors Go `Proposal.Encode`.
     */
    @Throws(Exception::class)
    fun encode(): ByteArray {
        val w = SlotCodec.ProposalWire(
            v = RosterProposal.VERSION.toLong(),
            slot = RosterProposal.SLOT_PROPOSAL,
            core = Base64Url.encode(core),
            usr = draft.usr,
            bprev = draft.bprev.ifEmpty { null },
            roster = roster,
            persons = LinkedHashMap(persons),
        )
        RosterProposal.proposalCounts(w)
        RosterProposal.proposalLists(w)
        val b = SlotCodec.marshal(w)
        if (b.size > RosterProposal.MAX_PROPOSAL_BYTES) {
            refuse(TOO_LARGE, "${b.size} bytes, max ${RosterProposal.MAX_PROPOSAL_BYTES}")
        }
        return b
    }
}

/**
 * The `cosig` slot: one cosig [entry] and the cosigner's person context (the closure of
 * the entry's bprev in its own log; empty when the entry needs none). Mirrors Go
 * `proposal.Cosig`.
 */
class Cosig(val entry: RosterSignature, val persons: Map<String, List<String>> = emptyMap()) {
    /**
     * Render this cosig as its slot payload, refusing one over the caps
     * ([ProposalReason.TOO_LARGE]) or out of canonical form ([ProposalReason.MALFORMED]).
     * Mirrors Go `Cosig.Encode`.
     */
    @Throws(Exception::class)
    fun encode(): ByteArray {
        val w = SlotCodec.CosigWire(
            v = RosterProposal.VERSION.toLong(),
            slot = RosterProposal.SLOT_COSIG,
            entry = SlotCodec.SigWire(entry.by, entry.usr, entry.bprev.ifEmpty { null }, entry.sig),
            persons = LinkedHashMap(persons),
        )
        RosterProposal.cosigCounts(w.persons)
        RosterProposal.personLists(w.persons.orEmpty())
        val b = SlotCodec.marshal(w)
        if (b.size > RosterProposal.MAX_COSIG_BYTES) {
            refuse(TOO_LARGE, "${b.size} bytes, max ${RosterProposal.MAX_COSIG_BYTES}")
        }
        return b
    }
}

/** [RosterProposal.context]'s output: the attachments for [RosterProposal.create]. */
data class ProposalContext(val roster: List<String>, val persons: Map<String, List<String>>)

/**
 * The slot payloads as Go's `encoding/json` reads and writes them. Reading a payload
 * that is not canonical must reach the same refusal Go reaches, and which refusal that
 * is depends on what Go's struct decoding makes of it: a case-variant `"V"` still sets
 * `v`, a later duplicate member wins, a `null` leaves a scalar alone, a type mismatch
 * fails the whole decode. This object reproduces those rules over a [GoJson] tree;
 * [canonical] then demands the payload be exactly the re-encoding of what it read.
 */
@Suppress("TooManyFunctions")
internal object SlotCodec {
    @Suppress("LongParameterList")
    class ProposalWire(
        var v: Long = 0,
        var slot: String = "",
        var core: String = "",
        var usr: String = "",
        var bprev: List<String>? = null,
        var roster: List<String>? = null,
        var persons: MutableMap<String, List<String>?>? = null,
    )

    class SigWire(var by: String = "", var usr: String = "", var bprev: List<String>? = null, var sig: String = "")

    class CosigWire(
        var v: Long = 0,
        var slot: String = "",
        val entry: SigWire = SigWire(),
        var persons: MutableMap<String, List<String>?>? = null,
    )

    /** A Go `UnmarshalTypeError`: the value does not fit the field. */
    private class Mismatch : Exception()

    /**
     * The byte cap, then Go's `readHeader`: the payload must be JSON (malformed), its `v`
     * [RosterProposal.VERSION] (bad_version) and its `slot` [slot] (malformed).
     */
    fun readHeader(raw: ByteArray, max: Int, slot: String): GoJson.Node {
        if (raw.size > max) refuse(TOO_LARGE, "${raw.size} bytes, max $max")
        val tree = GoJson.parse(raw.decodeToString()) ?: refuse(MALFORMED, "not JSON")
        var v = 0L
        var s = ""
        decoding {
            struct(tree, HEADER_FIELDS) { f, n ->
                if (f == "v") v = int(n, v) else s = str(n, s)
            }
        }
        if (v != RosterProposal.VERSION.toLong()) refuse(BAD_VERSION, "v $v")
        if (s != slot) refuse(MALFORMED, "slot \"$s\", want \"$slot\"")
        return tree
    }

    fun proposalWire(tree: GoJson.Node): ProposalWire {
        val w = ProposalWire()
        decoding {
            struct(tree, PROPOSAL_FIELDS) { f, n ->
                when (f) {
                    "v" -> w.v = int(n, w.v)
                    "slot" -> w.slot = str(n, w.slot)
                    "core" -> w.core = str(n, w.core)
                    "usr" -> w.usr = str(n, w.usr)
                    "bprev" -> w.bprev = strList(n, w.bprev)
                    "roster" -> w.roster = strList(n, w.roster)
                    else -> w.persons = personMap(n, w.persons)
                }
            }
        }
        return w
    }

    fun cosigWire(tree: GoJson.Node): CosigWire {
        val w = CosigWire()
        decoding {
            struct(tree, COSIG_FIELDS) { f, n ->
                when (f) {
                    "v" -> w.v = int(n, w.v)

                    "slot" -> w.slot = str(n, w.slot)

                    "entry" -> struct(n, SIG_FIELDS) { g, m ->
                        val e = w.entry
                        when (g) {
                            "by" -> e.by = str(m, e.by)
                            "usr" -> e.usr = str(m, e.usr)
                            "bprev" -> e.bprev = strList(m, e.bprev)
                            else -> e.sig = str(m, e.sig)
                        }
                    }

                    else -> w.persons = personMap(n, w.persons)
                }
            }
        }
        return w
    }

    /**
     * Go's `canonical`: a null or absent `roster`/`persons` is malformed, and the payload
     * must be exactly the encoding of what it parsed to.
     */
    fun canonical(raw: ByteArray, w: Any) {
        val b = when (w) {
            is ProposalWire -> {
                if (w.roster == null || w.persons == null) refuse(MALFORMED, "roster and persons are required")
                marshal(w)
            }

            is CosigWire -> {
                if (w.persons == null) refuse(MALFORMED, "persons is required")
                marshal(w)
            }

            else -> error("not a slot wire")
        }
        if (!b.contentEquals(raw)) refuse(MALFORMED, "not the canonical encoding")
    }

    /** Go's `json.Marshal(proposalWire)`. */
    fun marshal(w: ProposalWire): ByteArray {
        val sb = StringBuilder()
        sb.append("{\"v\":").append(w.v).append(",\"slot\":")
        GoJson.appendString(sb, w.slot)
        sb.append(",\"core\":")
        GoJson.appendString(sb, w.core)
        if (w.usr.isNotEmpty()) {
            sb.append(",\"usr\":")
            GoJson.appendString(sb, w.usr)
        }
        if (!w.bprev.isNullOrEmpty()) {
            sb.append(",\"bprev\":")
            list(sb, w.bprev)
        }
        sb.append(",\"roster\":")
        list(sb, w.roster)
        sb.append(",\"persons\":")
        map(sb, w.persons)
        return sb.append('}').toString().encodeToByteArray()
    }

    /** Go's `json.Marshal(cosigWire)` (the entry is `roster.Signature`). */
    fun marshal(w: CosigWire): ByteArray {
        val sb = StringBuilder()
        sb.append("{\"v\":").append(w.v).append(",\"slot\":")
        GoJson.appendString(sb, w.slot)
        sb.append(",\"entry\":{\"by\":")
        GoJson.appendString(sb, w.entry.by)
        if (w.entry.usr.isNotEmpty()) {
            sb.append(",\"usr\":")
            GoJson.appendString(sb, w.entry.usr)
        }
        if (!w.entry.bprev.isNullOrEmpty()) {
            sb.append(",\"bprev\":")
            list(sb, w.entry.bprev)
        }
        sb.append(",\"sig\":")
        GoJson.appendString(sb, w.entry.sig)
        sb.append("},\"persons\":")
        map(sb, w.persons)
        return sb.append('}').toString().encodeToByteArray()
    }

    private fun list(sb: StringBuilder, l: List<String>?) {
        if (l == null) {
            sb.append("null")
            return
        }
        sb.append('[')
        for ((i, s) in l.withIndex()) {
            if (i > 0) sb.append(',')
            GoJson.appendString(sb, s)
        }
        sb.append(']')
    }

    private fun map(sb: StringBuilder, m: Map<String, List<String>?>?) {
        if (m == null) {
            sb.append("null")
            return
        }
        sb.append('{')
        for ((i, k) in m.keys.sortedWith(GoJson::compareUtf8).withIndex()) {
            if (i > 0) sb.append(',')
            GoJson.appendString(sb, k)
            sb.append(':')
            list(sb, m[k])
        }
        sb.append('}')
    }

    // --- Go's struct decoding -----------------------------------------------------------

    private inline fun decoding(block: () -> Unit) {
        try {
            block()
        } catch (e: Mismatch) {
            refuse(MALFORMED, "a member has the wrong JSON type", e)
        }
    }

    /**
     * Decode an object into a struct with [fields]: each member sets the field it names
     * exactly or under Go's case folding, in document order (so a later duplicate wins);
     * unknown members are ignored; `null` leaves the struct alone.
     */
    private inline fun struct(n: GoJson.Node, fields: List<String>, set: (String, GoJson.Node) -> Unit) {
        when (n) {
            is GoJson.Null -> return

            is GoJson.Obj -> for ((k, v) in n.members) {
                val f = fields.firstOrNull { GoJson.foldsTo(k, it) } ?: continue
                set(f, v)
            }

            else -> throw Mismatch()
        }
    }

    /** An `int` field: an integer literal that fits int64; `null` leaves it alone. */
    private fun int(n: GoJson.Node, cur: Long): Long = when (n) {
        is GoJson.Null -> cur
        is GoJson.Num -> n.text.toLongOrNull() ?: throw Mismatch()
        else -> throw Mismatch()
    }

    private fun str(n: GoJson.Node, cur: String): String = when (n) {
        is GoJson.Null -> cur
        is GoJson.Str -> n.value
        else -> throw Mismatch()
    }

    /**
     * A `[]string` field: `null` sets nil; an array replaces the slice, an element `null`
     * keeping what the old slice held at that index (Go decodes into the existing
     * backing array), else "".
     */
    private fun strList(n: GoJson.Node, cur: List<String>?): List<String>? = when (n) {
        is GoJson.Null -> null

        is GoJson.Arr -> n.items.mapIndexed { i, e ->
            when (e) {
                is GoJson.Str -> e.value
                is GoJson.Null -> cur?.getOrNull(i) ?: ""
                else -> throw Mismatch()
            }
        }

        else -> throw Mismatch()
    }

    /**
     * A `map[string][]string` field: `null` sets nil; an object adds to the existing map
     * (keys exact, a later duplicate key wins, each value decoded fresh).
     */
    private fun personMap(n: GoJson.Node, cur: MutableMap<String, List<String>?>?): MutableMap<String, List<String>?>? =
        when (n) {
            is GoJson.Null -> null

            is GoJson.Obj -> (cur ?: LinkedHashMap()).also { m ->
                for ((k, v) in n.members) m[k] = strList(v, null)
            }

            else -> throw Mismatch()
        }

    private val HEADER_FIELDS = listOf("v", "slot")
    private val PROPOSAL_FIELDS = listOf("v", "slot", "core", "usr", "bprev", "roster", "persons")
    private val COSIG_FIELDS = listOf("v", "slot", "entry", "persons")
    private val SIG_FIELDS = listOf("by", "usr", "bprev", "sig")
}
