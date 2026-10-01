package one.rarebit.voidwhichbinds.auth

/**
 * The client-side policy for presenting a [DeviceCredential]: **re-mint and retry
 * once on `401`**, never fail hard on a stale proof.
 *
 * A relying party answers every `Device` refusal with the same undifferentiated
 * `401` — an expired proof, a not-yet-valid one (device clock behind), a revoked
 * cert, an unknown device. The first two are cured by a fresh proof; the rest are
 * not, and a second `401` is surfaced as-is. So one retry is the whole strategy.
 *
 * This is deliberately transport-agnostic — no OkHttp, no `HttpTransport`, no
 * coroutine runtime — so an OkHttp `Interceptor`, a Ktor plugin, a `URLSession`
 * wrapper and a plain blocking client all drive the SAME decision:
 *
 * - [next] is the pure state machine: given the attempt number and the status the
 *   server answered, either you are [Next.DONE] or you [Next.REFRESH_AND_RETRY].
 * - [execute] is the generic driver over any request/response type. It is `inline`,
 *   so [send] may be a blocking call or a `suspend` call — the caller's context decides.
 *
 * ```kotlin
 * // OkHttp interceptor, sketch:
 * override fun intercept(chain: Chain): Response = DeviceAuthPolicy.execute(
 *     credential,
 *     statusOf = { it.code },
 *     send = { header -> chain.proceed(chain.request().newBuilder().header("Authorization", header).build()) },
 * )
 * ```
 */
object DeviceAuthPolicy {

    /** The status a relying party answers a refused `Device` credential with. */
    const val UNAUTHORIZED = 401

    /** One send plus one re-mint-and-retry. */
    const val MAX_ATTEMPTS = 2

    /** What to do after a response. */
    enum class Next { DONE, REFRESH_AND_RETRY }

    /**
     * The pure decision: [attempt] is 1-based (the first send is attempt 1), [status]
     * is the HTTP status the server answered. Only a `401` on a non-final attempt is
     * retried; every other status — including a second `401` — is final.
     */
    fun next(status: Int, attempt: Int): Next =
        if (status == UNAUTHORIZED && attempt < MAX_ATTEMPTS) Next.REFRESH_AND_RETRY else Next.DONE

    /**
     * Send a request with [credential]'s live header value; on a `401`, [DeviceCredential.refresh]
     * (a forced fresh proof — on a phone this may show the biometric prompt) and send
     * again exactly once. Returns the final response, whatever its status.
     *
     * [statusOf] extracts the HTTP status from the response type [R]; [send] performs
     * the request with the given `Authorization` header value. Being `inline`, [send]
     * may suspend when called from a coroutine.
     */
    inline fun <R> execute(credential: DeviceCredential, statusOf: (R) -> Int, send: (headerValue: String) -> R): R {
        var attempt = 1
        var header = credential.headerValue()
        while (true) {
            val response = send(header)
            if (next(statusOf(response), attempt) == Next.DONE) return response
            attempt++
            header = credential.refresh().headerValue
        }
    }
}
