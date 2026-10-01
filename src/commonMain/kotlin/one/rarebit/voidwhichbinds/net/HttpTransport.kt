package one.rarebit.voidwhichbinds.net

/**
 * An opaque HTTP response: the status code and the raw body bytes. The network
 * clients here never parse a body they did not ask for, so the transport hands
 * back bytes and the client decides.
 */
class HttpResponse(val status: Int, val body: ByteArray)

/**
 * The pluggable HTTP seam, so `commonMain` stays engine-free and each platform
 * supplies its own transport (java.net.http on JVM/Android, NSURLSession on
 * Apple). The relay is human-paced, so [sleep] backs the poll loop in
 * [RelayClient.fetch] without pulling a coroutine runtime into this library.
 *
 * The calls are BLOCKING by deliberate choice: a blocking contract is the
 * lowest-risk shape that compiles identically on JVM, Android and Kotlin/Native,
 * and an app drives them off the main thread (Dispatchers.IO / a background
 * queue). A suspend variant is a thin wrapper a caller can add later.
 */
interface HttpTransport {
    /** GET url. Content is returned as raw bytes with the status. */
    fun get(url: String): HttpResponse

    /** POST url with an optional body. */
    fun post(url: String, body: ByteArray? = null, contentType: String? = null): HttpResponse

    /** PUT url with a body. */
    fun put(url: String, body: ByteArray, contentType: String? = null): HttpResponse

    /**
     * DELETE url with an optional body — the notify plane's unsubscribe carries the
     * device cert in a JSON body (void-which-binds-go reads it on DELETE). A default is
     * provided so existing transports and test fakes need not implement it (removing
     * it would break consumers' fakes); the real JVM transport and the iOS app's
     * `URLSessionHttpTransport` override it.
     */
    fun delete(url: String, body: ByteArray? = null, contentType: String? = null): HttpResponse =
        throw UnsupportedOperationException("this transport does not implement DELETE")

    /** Sleep the given milliseconds — backs the relay fetch poll loop. */
    fun sleep(millis: Long)
}
