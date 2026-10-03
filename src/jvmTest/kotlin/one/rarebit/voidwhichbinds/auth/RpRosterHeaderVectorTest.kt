package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The CLIENT half of void-which-binds-go's org-trust vectors (ADR-0016, G5):
 * `testvectors/vectors/rp-roster/` (pinned by `VOID_WHICH_BINDS_GO_REF`), copied verbatim
 * into `src/jvmTest/resources/vectors/rp-roster/`. Each file is a sequence of requests
 * against one RP; the RP's evaluation (`rp.Roster`, `CheckOrg`) is server-side and not
 * ported. What a device must get right is the headers, so for every request in every
 * file this parses the header values in the order Go's replay does
 * (`rp/roster_vectors_test.go`: membership, then — off the truststore path — org, then
 * roster):
 *
 * - a parse refusal must be the request's expected `error`, with Go's reason word;
 * - otherwise every value re-formats from its parsed contents to the exact bytes, and
 *   an [OrgRequest] built from the parsed contents carries the same org and op sets
 *   (in op-hash order), whose header values parse back to them.
 */
@Suppress("UNCHECKED_CAST")
class RpRosterHeaderVectorTest {

    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/rp-roster") ?: error("vectors/rp-roster missing")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty()
            .map { it.name.removeSuffix(".json") }.sorted()
            .also { check(it.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS vectors, found ${it.size}" } }
    }

    private fun load(name: String): Map<String, Any> {
        val raw = javaClass.getResourceAsStream("/vectors/rp-roster/$name.json")!!.readBytes().decodeToString()
        return MiniJson.parseObject(raw).also { assertEquals(name, it["name"], "file stem must equal its name") }
    }

    private fun <T> parsed(block: () -> T): Result<T> = try {
        Result.success(block())
    } catch (e: RpHeaderException) {
        Result.failure(e)
    }

    private fun reason(r: Result<*>): String = (r.exceptionOrNull() as RpHeaderException).failure.reason

    private fun hashOrder(toks: List<String>): List<String> = toks.distinct().sortedBy { MembershipOp.hash(it) }

    @Test
    @Suppress("CyclomaticComplexMethod", "LongMethod", "NestedBlockDepth", "LoopWithTooManyJumpStatements")
    fun everyRequestsHeadersRoundTripAndRefuseAsGo() {
        var formatted = 0
        var refused = 0
        for (name in cases) {
            val v = load(name)
            for (q in v["requests"] as List<Map<String, Any>>) {
                val label = "$name/${q["label"]}"
                val mode = q["mode"] as String
                val headers = (q["headers"] as Map<String, String>?).orEmpty()
                val expected = (q["expect"] as Map<String, Any>)["error"] as String?
                if (mode in HEADERLESS_MODES) {
                    assertTrue(headers.isEmpty(), "$label: a $mode request carries no headers")
                    continue
                }
                assertTrue(
                    headers.keys.all { it in KNOWN_HEADERS },
                    "$label: unknown header in ${headers.keys}",
                )

                val rawMembership = headers[RpHeaders.MEMBERSHIP_HEADER]
                val membership = parsed { RpHeaders.parseMembershipHeader(rawMembership.orEmpty()) }
                if (membership.isFailure) {
                    assertEquals(expected, reason(membership), "$label: membership header refusal")
                    refused++
                    continue
                }
                val ops = membership.getOrThrow()
                if (rawMembership != null) {
                    assertEquals(rawMembership, RpHeaders.formatMembershipHeader(ops), "$label: membership bytes")
                }
                if (mode == "truststore") {
                    assertTrue(RpHeaders.ORG_HEADER !in headers, "$label: a truststore request carries the org header")
                    formatted++
                    continue
                }

                val rawOrg = headers[RpHeaders.ORG_HEADER]
                val org = parsed { RpHeaders.parseOrgHeader(rawOrg.orEmpty()) }
                if (org.isFailure) {
                    assertEquals(expected, reason(org), "$label: org header refusal")
                    refused++
                    continue
                }
                assertEquals(rawOrg, RpHeaders.formatOrgHeader(org.getOrThrow()), "$label: org bytes")

                val rawRoster = headers[RpHeaders.ROSTER_HEADER]
                val roster = parsed { RpHeaders.parseRosterHeader(rawRoster.orEmpty()) }
                if (roster.isFailure) {
                    assertEquals(expected, reason(roster), "$label: roster header refusal")
                    // The client helper refuses the same contents before sending them,
                    // unless de-duplicating brings them under the cap (`count` is one
                    // op 17 times): then what it sends is a header Go accepts.
                    val toks = rawRoster.orEmpty().split(',').filter { it.isNotEmpty() }
                    val distinct = toks.distinct()
                    if (distinct.size > RpHeaders.MAX_PRESENTED_ROSTER_OPS ||
                        distinct.any { it.encodeToByteArray().size > RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES }
                    ) {
                        val e = assertFailsWith<RpHeaderException>("$label: OrgRequest over the roster cap") {
                            OrgRequest(org.getOrThrow(), toks, ops)
                        }
                        assertEquals(expected, e.failure.reason, label)
                    } else {
                        val sent = OrgRequest(org.getOrThrow(), toks, ops).presentedHeaders()
                        assertEquals(
                            hashOrder(distinct),
                            RpHeaders.parseRosterHeader(sent.getValue(RpHeaders.ROSTER_HEADER)),
                            "$label: OrgRequest de-duplicates under the cap",
                        )
                    }
                    refused++
                    continue
                }
                val rops = roster.getOrThrow()
                if (rawRoster != null) {
                    assertEquals(rawRoster, RpHeaders.formatRosterHeader(rops), "$label: roster bytes")
                }

                // The client helper: same org, same op sets, in hash order, parsing back.
                val req = OrgRequest(org.getOrThrow(), rops, ops)
                val sent = req.headers(DeviceCredential.headerValue(q["credential"] as String, POSSESSION_STANDIN))
                assertEquals(rawOrg, sent[RpHeaders.ORG_HEADER], "$label: OrgRequest org header")
                assertEquals(hashOrder(rops), req.rosterOps, "$label: OrgRequest roster ops")
                assertEquals(hashOrder(ops), req.membershipOps, "$label: OrgRequest person ops")
                assertEquals(
                    req.rosterOps,
                    RpHeaders.parseRosterHeader(sent[RpHeaders.ROSTER_HEADER].orEmpty()),
                    "$label: OrgRequest roster header parses back",
                )
                assertEquals(
                    req.membershipOps,
                    RpHeaders.parseMembershipHeader(sent[RpHeaders.MEMBERSHIP_HEADER].orEmpty()),
                    "$label: OrgRequest membership header parses back",
                )
                assertEquals(rawRoster != null, RpHeaders.ROSTER_HEADER in sent, "$label: roster header presence")
                assertEquals(
                    rawMembership != null,
                    RpHeaders.MEMBERSHIP_HEADER in sent,
                    "$label: membership header presence",
                )
                formatted++
            }
        }
        // roster-header-over-cap's two requests are the only header refusals.
        assertEquals(2, refused, "header refusals across the vectors")
        if (formatted < MIN_FORMATTED) fail("only $formatted requests carried headers")
    }

    private companion object {
        const val MIN_VECTORS = 26
        const val MIN_FORMATTED = 30
        const val POSSESSION_STANDIN = "proof"
        val HEADERLESS_MODES = setOf("pin", "unpin", "commit", "grant")
        val KNOWN_HEADERS = setOf(RpHeaders.ORG_HEADER, RpHeaders.ROSTER_HEADER, RpHeaders.MEMBERSHIP_HEADER)
    }
}
