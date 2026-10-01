package one.rarebit.voidwhichbinds.net

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.WebLogin
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * CI-safe coverage of the network clients: a faithful in-JVM mock of the
 * void-which-binds-go relay (an opaque write-once slot store) and of the weblogin RP,
 * over real HTTP through [JdkHttpTransport]. The live cross-language proof against
 * a running void-which-binds-go is in GoInteropTest (skipped when `go` is absent).
 */
class NetworkClientsTest {
    private lateinit var server: HttpServer
    private lateinit var base: String
    private val http = JdkHttpTransport()

    // relay state: "id/role/type" -> bytes
    private val slots = ConcurrentHashMap<String, ByteArray>()

    // weblogin state
    private val approved = ConcurrentHashMap<String, Boolean>()

    @BeforeTest
    fun start() {
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex -> route(ex) }
        server.executor = java.util.concurrent.Executors.newFixedThreadPool(8)
        server.start()
        base = "http://127.0.0.1:${server.address.port}"
    }

    @AfterTest
    fun stop() = server.stop(0)

    private fun body(ex: HttpExchange): ByteArray = ex.requestBody.readBytes()
    private fun send(ex: HttpExchange, code: Int, b: ByteArray = ByteArray(0)) {
        if (b.isEmpty()) {
            ex.sendResponseHeaders(code, -1)
        } else {
            ex.sendResponseHeaders(code, b.size.toLong())
            ex.responseBody.use { it.write(b) }
        }
        ex.close()
    }

    private fun route(ex: HttpExchange) {
        val p = ex.requestURI.path
        val m = ex.requestMethod
        when {
            m == "POST" && p == "/v1/sessions" -> send(ex, 200, """{"session_id":"s1"}""".encodeToByteArray())

            p.startsWith("/v1/sessions/") -> {
                val key = p.removePrefix("/v1/sessions/") // id/role/type
                if (m == "PUT") {
                    if (slots.putIfAbsent(key, body(ex)) != null) send(ex, 409) else send(ex, 204)
                } else {
                    val v = slots[key]
                    if (v == null) send(ex, 404) else send(ex, 200, v)
                }
            }

            m == "POST" && p == "/login" ->
                send(ex, 200, """{"id":"L1","qr":"void-which-binds:login?rp=$base&id=L1"}""".encodeToByteArray())

            p == "/login/L1/challenge" -> {
                val nonce = Base64Url.encode(ByteArray(32) { 0x11 })
                send(
                    ex,
                    200,
                    """{"id":"L1","nonce":"$nonce","audience":"aud","expires_at":4102444800}""".encodeToByteArray(),
                )
            }

            m == "POST" && p == "/login/L1/approve" -> {
                val o = MiniJson.parseObject(body(ex).decodeToString())
                // record that a well-formed assertion arrived
                approved["L1"] =
                    (o["cert"] as? String)?.isNotEmpty() == true && (o["sig"] as? String)?.isNotEmpty() == true
                send(ex, if (approved["L1"] == true) 204 else 401)
            }

            p == "/login/L1" -> {
                val ok = approved["L1"] == true
                val j = if (ok) """{"status":"approved","token":"TOK123","user":"ed25519:aa"}""" else """{"status":"pending"}"""
                send(ex, 200, j.encodeToByteArray())
            }

            else -> send(ex, 404)
        }
    }

    @Test
    fun pairflowHandshakeMatchesOverTheRelay() {
        val session = RelayClient.createSession(http, base)
        assertEquals("s1", session)

        val user = Ed25519Engine.generate()
        val dev = Ed25519Engine.generate()
        val devEnc = ByteArray(32) { (it + 3).toByte() } // opaque enc bytes; SAS frames them identically both sides
        val salt = ByteArray(32) { (it * 7 + 1).toByte() }

        val initRelay = RelayClient(http, base, session, RelayClient.ROLE_INITIATOR, pollIntervalMillis = 10)
        val respRelay = RelayClient(http, base, session, RelayClient.ROLE_RESPONDER, pollIntervalMillis = 10)
        val initiator = PairflowInitiator(
            initRelay,
            PairflowAuthority.Genesis({
                Ed25519Engine.sign(user.privateSeed, it)
            }, user.publicKey, emptyList(), 7_776_000L),
            salt,
            1_724_700_000L,
        )
        val responder =
            PairflowResponder(
                respRelay,
                KeyRef.ed25519(user.publicKey).render(),
                dev.publicKey,
                devEnc,
                salt,
                1_724_700_000L,
            )

        var sasInit = ""
        var sasResp = ""
        val ti = Thread { sasInit = initiator.handshake() }
        val tr = Thread { sasResp = responder.handshake() }
        ti.start()
        tr.start()
        ti.join(10_000)
        tr.join(10_000)

        assertEquals(sasInit, sasResp, "SAS must match over the relay")
        assertEquals(Pairing.DIGITS, sasInit.length)
    }

    @Test
    fun webLoginDeviceApprovesAndBrowserGetsToken() {
        val rp = WebLoginClient(http, base)
        val created = rp.createLogin()
        assertEquals("L1", created.id)
        assertTrue(created.qr.startsWith("void-which-binds:login?"))
        assertEquals("pending", rp.poll(created.id).status)

        // Device: fetch the challenge and approve with a signed assertion.
        val dev = Ed25519Engine.generate()
        val chal = rp.fetchChallenge(created.id)
        val assertion = WebLogin.signAssertion(chal, "CERT.TOKEN") { Ed25519Engine.sign(dev.privateSeed, it) }
        rp.approve(created.id, assertion)

        val poll = rp.poll(created.id)
        assertEquals("approved", poll.status)
        assertEquals("TOK123", poll.token)
    }
}
