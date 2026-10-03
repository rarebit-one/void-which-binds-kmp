package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.approval.Approval
import one.rarebit.voidwhichbinds.approval.FetchNonce
import one.rarebit.voidwhichbinds.approval.FetchNonceResponse
import one.rarebit.voidwhichbinds.approval.FetchRequest
import one.rarebit.voidwhichbinds.approval.FetchResponse
import one.rarebit.voidwhichbinds.approval.Handle
import one.rarebit.voidwhichbinds.approval.OpenedApproval
import one.rarebit.voidwhichbinds.auth.OrgRequest

/**
 * The broker was reached but answered an approval call with a status other than the
 * expected one (e.g. `429` from `fetch-nonce` over its rate limit). [op] names the call.
 * A transport failure surfaces as the platform transport's own exception instead.
 */
class ApprovalHttpException(val status: Int, val op: String) : RuntimeException("approval: $op: HTTP $status")

/**
 * The broker refused a fetch. ADR-0019 makes every refusal identical on the wire — `404`
 * with exactly [Approval.FETCH_REFUSAL_BODY] — whether the handle is unknown, the
 * challenge expired or approved, the proof bad, the nonce spent, or the key another
 * person's; so this carries no reason, and there is none to learn.
 */
class ApprovalFetchRefusedException : RuntimeException("approval: fetch refused (not_found)")

/**
 * The approver's client for the authenticated fetch (void-which-binds-go ADR-0019,
 * amended #98): what Cruciform runs after an `approve` wake ([Approval.parseApprove]).
 *
 * ```
 * POST {broker}/approval/fetch-nonce                       -> 200 {"nonce"}       (429 over the limit)
 * POST {broker}/approval/fetch  {handle,nonce,credential,ops,roster,proof}
 *                                                          -> 200 {"challenge":{…},"action":{…}}
 *                                                          |  404 {"error":"not_found"} (every refusal)
 * ```
 *
 * [brokerBase] is the broker the approver holds approver standing at — from its own
 * enrolment, never from the tuple — and [audience] is that broker's origin, which the
 * fetch proof is bound to (a proof made for one broker fails at another). An approver
 * enrolled at several brokers tries each in turn with its own client.
 *
 * The fetch is authenticated through the broker's `CheckOrg` with its own configured
 * org, so the request carries no org header: the presented person and roster ops ride
 * in the body (`ops`, `roster`), taken from an [OrgRequest]'s de-duplicated, hash-ordered
 * lists. [fetch] opens the answer ([FetchResponse.open]) before returning it, so what it
 * returns has a recomputed digest and is safe to display and sign.
 */
class ApprovalClient
@Throws(Exception::class)
constructor(
    private val http: HttpTransport,
    brokerBase: String,
    val audience: String,
) {
    private val base = brokerBase.trimEnd('/')

    init {
        require(audience.isNotEmpty()) { "approval: the broker's audience (origin) is required" }
    }

    /** `POST /approval/fetch-nonce`: a fresh single-use nonce, valid for [Approval.FETCH_NONCE_TTL_SECONDS]. */
    @Throws(Exception::class)
    fun fetchNonce(): FetchNonce {
        val resp = http.post("$base/approval/fetch-nonce")
        if (resp.status != HTTP_OK) throw ApprovalHttpException(resp.status, "fetch nonce")
        return FetchNonceResponse.parse(resp.body)
    }

    /**
     * `POST /approval/fetch` with [request], then [FetchResponse.open]. Throws
     * [ApprovalFetchRefusedException] for the one refusal, [ApprovalHttpException] for any
     * other unexpected status, and [Approval.ApprovalException] for an answer that does
     * not open (a malformed challenge, or an action that does not match it).
     */
    @Throws(Exception::class)
    fun fetch(request: FetchRequest): OpenedApproval {
        val resp = http.post("$base/approval/fetch", request.toJson(), JSON)
        if (resp.status == Approval.FETCH_REFUSAL_STATUS) throw ApprovalFetchRefusedException()
        if (resp.status != HTTP_OK) throw ApprovalHttpException(resp.status, "fetch")
        return FetchResponse.parse(resp.body).open()
    }

    /**
     * The whole fetch for an Ed25519 approver: a nonce, the proof over
     * [Approval.fetchPreimage] for [audience] signed by [signer] (public key
     * [signerPublicKey]), and [fetch]. A passkey approver runs the same steps itself:
     * [fetchNonce], [Approval.fetchPasskeyChallenge], its platform assertion,
     * [Approval.encodeEnvelope] as the proof, then [fetch].
     */
    @Suppress("LongParameterList")
    @Throws(Exception::class)
    fun fetchWithEd25519(
        handle: Handle,
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        credential: String,
        presented: OrgRequest? = null,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): OpenedApproval {
        val nonce = fetchNonce()
        val proof = Approval.signFetchProofWith(signer, signerPublicKey, audience, handle, nonce, verifier)
        return fetch(request(handle, nonce, credential, proof, presented))
    }

    /** The [FetchRequest] for [handle] and [nonce], with [presented]'s ops in the body. */
    fun request(handle: Handle, nonce: FetchNonce, credential: String, proof: String, presented: OrgRequest? = null) =
        FetchRequest(
            handle,
            nonce,
            credential,
            presented?.membershipOps.orEmpty(),
            presented?.rosterOps.orEmpty(),
            proof,
        )

    private companion object {
        const val HTTP_OK = 200
        const val JSON = "application/json"
    }
}
