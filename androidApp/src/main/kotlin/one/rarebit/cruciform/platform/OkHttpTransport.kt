package one.rarebit.cruciform.platform

import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import java.util.concurrent.TimeUnit

/**
 * The Android `HttpTransport` — OkHttp, synchronous by design (the library's
 * contract is blocking and the engine drives it off the main thread). Backs the
 * relay poll loop and the RP challenge/approve calls. Returns raw bytes + status;
 * it never parses a body, matching the seam.
 */
class OkHttpTransport(private val client: OkHttpClient = defaultClient()) : HttpTransport {

    override fun get(url: String): HttpResponse = execute(Request.Builder().url(url).get().build())

    override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
        val rb = (body ?: ByteArray(0)).toRequestBody(contentType?.toMediaTypeOrNull())
        return execute(Request.Builder().url(url).post(rb).build())
    }

    override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse {
        val rb = body.toRequestBody(contentType?.toMediaTypeOrNull())
        return execute(Request.Builder().url(url).put(rb).build())
    }

    override fun delete(url: String, body: ByteArray?, contentType: String?): HttpResponse {
        // The notify-plane unsubscribe carries the device cert in the body; OkHttp
        // sends a DELETE body when one is provided.
        val rb = body?.toRequestBody(contentType?.toMediaTypeOrNull())
        return execute(Request.Builder().url(url).delete(rb).build())
    }

    override fun sleep(millis: Long) {
        try {
            Thread.sleep(millis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private fun execute(request: Request): HttpResponse = client.newCall(request).execute().use { resp ->
        HttpResponse(resp.code, resp.body?.bytes() ?: ByteArray(0))
    }

    private companion object {
        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .callTimeout(30, TimeUnit.SECONDS)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
