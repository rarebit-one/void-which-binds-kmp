import Foundation
import VoidWhichBinds

/// The iOS `HttpTransport` actual: a `URLSession`-backed implementation of the
/// Kotlin transport seam the network clients + coordinators drive. The Kotlin
/// contract is **blocking** (get/post/put/delete return synchronously, and the relay
/// poll loop calls `sleep`), so each call waits on a semaphore. The completion
/// handler runs on a background `URLSession` queue, so the wait must NOT happen on
/// the main thread — always call the coordinators off-main (a `Task.detached` /
/// background `DispatchQueue`), exactly as the Android side runs them on
/// `Dispatchers.IO`.
///
/// > Type-checked against the exported `VoidWhichBinds.xcframework`; runs on a
/// > device/simulator.
public final class URLSessionHttpTransport: NSObject, HttpTransport {

    private let session: URLSession
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 65) {
        self.timeout = timeout
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.waitsForConnectivity = true
        self.session = URLSession(configuration: config)
    }

    public func get(url: String) -> HttpResponse {
        perform(url: url, method: "GET", body: nil, contentType: nil)
    }

    public func post(url: String, body: KotlinByteArray?, contentType: String?) -> HttpResponse {
        perform(url: url, method: "POST", body: body?.toData(), contentType: contentType)
    }

    public func put(url: String, body: KotlinByteArray, contentType: String?) -> HttpResponse {
        perform(url: url, method: "PUT", body: body.toData(), contentType: contentType)
    }

    /// DELETE with an optional body — `NotifyClient.unsubscribe` sends the device
    /// cert as JSON on DELETE (void-which-binds-go reads it). The Kotlin interface's default
    /// throws `UnsupportedOperationException`, so this override is what makes
    /// unsubscribe work on iOS.
    public func delete(url: String, body: KotlinByteArray?, contentType: String?) -> HttpResponse {
        perform(url: url, method: "DELETE", body: body?.toData(), contentType: contentType)
    }

    public func sleep(millis: Int64) {
        Thread.sleep(forTimeInterval: Double(millis) / 1000.0)
    }

    // MARK: -

    private func perform(url: String, method: String, body: Data?, contentType: String?) -> HttpResponse {
        guard let u = URL(string: url) else {
            return HttpResponse(status: 0, body: Data().toKotlinByteArray())
        }
        var request = URLRequest(url: u, timeoutInterval: timeout)
        request.httpMethod = method
        if let body { request.httpBody = body }
        if let contentType { request.setValue(contentType, forHTTPHeaderField: "Content-Type") }

        let semaphore = DispatchSemaphore(value: 0)
        var status: Int32 = 0
        var payload = Data()
        let task = session.dataTask(with: request) { data, response, _ in
            if let http = response as? HTTPURLResponse { status = Int32(http.statusCode) }
            if let data { payload = data }
            semaphore.signal()
        }
        task.resume()
        semaphore.wait()
        return HttpResponse(status: status, body: payload.toKotlinByteArray())
    }
}
