package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.GoCheckout
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Labels
import one.rarebit.voidwhichbinds.Pairing
import one.rarebit.voidwhichbinds.WebLogin
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.net.ServerSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The CROSS-LANGUAGE proof: drive a LIVE void-which-binds-go over HTTP from the Kotlin
 * clients. Skipped (not failed) when `go` or the void-which-binds-go checkout is absent —
 * so CI, which has neither, stays green — and RUN locally where both exist.
 *
 * Builds the `void-which-binds` CLI once, then:
 *  - relay: two Kotlin pairflow sides pair through the REAL Go relay → SAS match.
 *  - weblogin: a Kotlin device approves a login on the REAL Go RP, which verifies
 *    the Kotlin-signed cert + assertion and mints a token → proves Go accepts
 *    Kotlin's cert (v2) and assertion byte-for-byte.
 */
class GoInteropTest {
    private val goDir = GoCheckout.dir
    private fun goAvailable(): Boolean = goDir.isDirectory && System.getenv("PATH").orEmpty().split(File.pathSeparator)
        .any { File(it, "go").canExecute() }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun buildCli(): File {
        // The binary is ~11 MB and /tmp is often RAM-backed: remove it when the test JVM exits.
        val out = File.createTempFile("vb-interop", "").apply {
            delete()
            deleteOnExit()
        }
        val p = ProcessBuilder("go", "build", "-o", out.absolutePath, GoCheckout.CLI_PACKAGE)
            .directory(goDir).redirectErrorStream(true).start()
        val log = p.inputStream.readBytes().decodeToString()
        assertEquals(0, p.waitFor(), "go build failed: $log")
        return out
    }

    private fun waitReady(within: Long = 20_000, check: () -> Boolean) {
        val http = JdkHttpTransport()
        val deadline = System.currentTimeMillis() + within
        while (System.currentTimeMillis() < deadline) {
            try {
                if (check()) return
            } catch (_: Exception) {}
            http.sleep(100)
        }
        throw IllegalStateException("server not ready within ${within}ms")
    }

    @Test
    fun pairflowPairsThroughLiveGoRelay() {
        assumeTrue(goAvailable(), "void-which-binds-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val port = freePort()
        val base = "http://127.0.0.1:$port"
        val proc = ProcessBuilder(cli.absolutePath, "relay", "--addr", "127.0.0.1:$port")
            .redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$base/v1/sessions").status == 200 }

            val session = RelayClient.createSession(http, base)
            val user = Ed25519Engine.generate()
            val dev = Ed25519Engine.generate()
            val devEnc = ByteArray(32) { (it + 5).toByte() }
            val salt = ByteArray(32) { (it * 3 + 2).toByte() }
            val init = PairflowInitiator(
                RelayClient(http, base, session, RelayClient.ROLE_INITIATOR, pollIntervalMillis = 20),
                PairflowAuthority.Genesis({
                    Ed25519Engine.sign(user.privateSeed, it)
                }, user.publicKey, emptyList(), 7_776_000L),
                salt,
                1_724_700_000L,
            )
            val resp = PairflowResponder(
                RelayClient(http, base, session, RelayClient.ROLE_RESPONDER, pollIntervalMillis = 20),
                KeyRef.ed25519(user.publicKey).render(),
                dev.publicKey,
                devEnc,
                salt,
                1_724_700_000L,
            )
            var a = ""
            var b = ""
            val ti = Thread { a = init.handshake() }
            val tr = Thread { b = resp.handshake() }
            ti.start()
            tr.start()
            ti.join(15_000)
            tr.join(15_000)
            assertEquals(a, b, "SAS must match through the live Go relay")
            assertEquals(Pairing.DIGITS, a.length)
        } finally {
            proc.destroyForcibly()
        }
    }

    @Test
    fun deviceApprovesLoginOnLiveGoRp() {
        assumeTrue(goAvailable(), "void-which-binds-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val port = freePort()
        val base = "http://127.0.0.1:$port"

        // A Kotlin-minted user identity the Go RP will pin.
        val user = Ed25519Engine.generate()
        val userId = KeyRef.ed25519(user.publicKey).render()

        val proc = ProcessBuilder(cli.absolutePath, "login-serve", "--addr", "127.0.0.1:$port", "--pin", userId)
            .redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$base/login").status == 200 }

            val rp = WebLoginClient(http, base)
            val created = rp.createLogin()

            // The Kotlin device: a fresh signing key + a cert the user signs (v2).
            val dev = Ed25519Engine.generate()
            val now = System.currentTimeMillis() / 1000
            val certToken = Cert(
                version = Labels.CERT_VERSION, // 2 — required by Go's CertUser
                user = KeyRef.ed25519(user.publicKey),
                device = KeyRef.ed25519(dev.publicKey),
                deviceEnc = KeyRef.x25519(ByteArray(32) { (it + 9).toByte() }),
                issuedAt = now,
                expiresAt = now + 3600,
            ).encode { msg -> Ed25519Engine.sign(user.privateSeed, msg) }

            val chal = rp.fetchChallenge(created.id)
            val assertion = WebLogin.signAssertion(chal, certToken) { Ed25519Engine.sign(dev.privateSeed, it) }
            rp.approve(created.id, assertion) // Go verifies cert (rp) + assertion sig; 204 or throws

            val poll = rp.poll(created.id)
            assertEquals("approved", poll.status, "the Go RP must approve a valid Kotlin assertion")
            assertTrue(!poll.token.isNullOrEmpty(), "the Go RP must mint a session token")
            assertEquals(userId, poll.user, "the authenticated principal is the pinned Kotlin user")
        } finally {
            proc.destroyForcibly()
        }
    }

    @Test
    fun deviceApprovesNumberMatchLoginOnLiveGoRp() {
        assumeTrue(goAvailable(), "void-which-binds-go / go not available — skipping cross-language test")
        val cli = buildCli()
        val port = freePort()
        val base = "http://127.0.0.1:$port"

        val user = Ed25519Engine.generate()
        val userId = KeyRef.ed25519(user.publicKey).render()

        val proc = ProcessBuilder(cli.absolutePath, "login-serve", "--addr", "127.0.0.1:$port", "--pin", userId)
            .redirectErrorStream(true).start()
        try {
            val http = JdkHttpTransport()
            waitReady { http.post("$base/login").status == 200 }

            val rp = WebLoginClient(http, base)
            // As the INITIATING surface: create a number-matching login and learn the
            // true number the browser would display.
            val created = rp.createNumberMatchLogin()
            val trueNumber = created.matchNumber

            // A Kotlin device cert the Go RP pins.
            val dev = Ed25519Engine.generate()
            val now = System.currentTimeMillis() / 1000
            val certToken = Cert(
                version = Labels.CERT_VERSION,
                user = KeyRef.ed25519(user.publicKey),
                device = KeyRef.ed25519(dev.publicKey),
                deviceEnc = KeyRef.x25519(ByteArray(32) { (it + 9).toByte() }),
                issuedAt = now,
                expiresAt = now + 3600,
            ).encode { msg -> Ed25519Engine.sign(user.privateSeed, msg) }

            // As the PHONE: the fetched challenge carries the candidate set but NOT the
            // true number (the Go handler withholds it — origin-binding).
            val chal = rp.fetchChallenge(created.id)
            assertTrue(chal.isNumberMatch, "the Go RP must send a candidate set for a v2 login")
            assertTrue(chal.candidates.contains(trueNumber), "the true number must be among the candidates")

            // Tapping the true number authenticates; the Go RP verifies the v2 binding.
            val ok = WebLogin.signAssertionV2(chal, trueNumber, certToken) { Ed25519Engine.sign(dev.privateSeed, it) }
            rp.approve(created.id, ok)
            val poll = rp.poll(created.id)
            assertEquals("approved", poll.status, "the Go RP must approve a correct number-match")
            assertEquals(userId, poll.user)

            // A SECOND, fresh login where the phone taps a DECOY must be refused by Go
            // (ErrNumberMismatch → the approve endpoint returns non-204).
            val created2 = rp.createNumberMatchLogin()
            val chal2 = rp.fetchChallenge(created2.id)
            val decoy = chal2.candidates.first { it != created2.matchNumber }
            val bad = WebLogin.signAssertionV2(chal2, decoy, certToken) { Ed25519Engine.sign(dev.privateSeed, it) }
            assertFailsWith<IllegalArgumentException> { rp.approve(created2.id, bad) }
            assertEquals("pending", rp.poll(created2.id).status, "a decoy tap must not authenticate on Go")
        } finally {
            proc.destroyForcibly()
        }
    }
}
