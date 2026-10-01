package one.rarebit.voidwhichbinds.net

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.time.Duration
import java.net.http.HttpResponse as JdkResponse

/**
 * A [HttpTransport] backed by java.net.http (JDK 11+). The dev/test transport on
 * JVM and Android; Apple targets supply an NSURLSession-backed actual.
 */
class JdkHttpTransport(
    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build(),
    private val requestTimeout: Duration = Duration.ofSeconds(30),
) : HttpTransport {

    private fun send(req: HttpRequest): HttpResponse {
        val r = client.send(req, JdkResponse.BodyHandlers.ofByteArray())
        return HttpResponse(r.statusCode(), r.body())
    }

    override fun get(url: String): HttpResponse = send(base(url).GET().build())

    override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
        val pub = if (body == null) {
            HttpRequest.BodyPublishers.noBody()
        } else {
            HttpRequest.BodyPublishers.ofByteArray(body)
        }
        return send(withType(base(url).POST(pub), contentType).build())
    }

    override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse =
        send(withType(base(url).PUT(HttpRequest.BodyPublishers.ofByteArray(body)), contentType).build())

    override fun delete(url: String, body: ByteArray?, contentType: String?): HttpResponse {
        val pub = if (body == null) {
            HttpRequest.BodyPublishers.noBody()
        } else {
            HttpRequest.BodyPublishers.ofByteArray(body)
        }
        return send(withType(base(url).method("DELETE", pub), contentType).build())
    }

    override fun sleep(millis: Long) = Thread.sleep(millis)

    private fun base(url: String): HttpRequest.Builder = HttpRequest.newBuilder(URI.create(url)).timeout(requestTimeout)

    private fun withType(b: HttpRequest.Builder, contentType: String?): HttpRequest.Builder =
        if (contentType != null) b.header("Content-Type", contentType) else b
}
