package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.WebLogin
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * The RP was **reached** but returned a non-success status for a weblogin call. It is
 * distinct from a transport failure (unreachable host, TLS error, timeout, a
 * cleartext-blocked URL) — those surface as the platform transport's own exception — so
 * a caller can tell "the site refused this" from "couldn't reach the site" and show the
 * right message. [status] is the HTTP code; [op] names the call (e.g. "fetch challenge").
 */
class WebLoginHttpException(val status: Int, val op: String) : RuntimeException("weblogin: $op: HTTP $status")

/**
 * Client for the Void-Which-Binds web QR-login (void-which-binds-go `weblogin`): the DEVICE side
 * (approve a login) and, for a browser stand-in, the create/poll side.
 *
 * Wire (byte-identical to void-which-binds-go/weblogin/handler.go):
 * ```
 * POST {rp}/login                       -> { "id", "qr" }                 (browser)
 * POST {rp}/login?mode=number-match      -> { "id", "qr", "match_number" } (browser)
 * GET  {rp}/login/{id}                    -> { "status", "token"?, "user"? } (browser polls)
 * GET  {rp}/login/{id}/challenge          -> { id, nonce(b64url), audience, expires_at, candidates? } (device)
 * POST {rp}/login/{id}/approve  {cert,sig[,match_number]}  -> 204          (device)
 * ```
 * The device path is the app's job: [fetchChallenge] then [approve] with an
 * assertion signed via [WebLogin.signAssertion] / [WebLogin.signAssertionV2]. The
 * browser path ([createLogin] / [createNumberMatchLogin] / [poll]) is here so a
 * test — or an in-app WebView shim — can drive the whole flow.
 *
 * Number-matching (v2, ADR-0006): [createNumberMatchLogin] returns the true match
 * number to the INITIATING surface only; [fetchChallenge] gives the phone the
 * shuffled [WebLogin.Challenge.candidates] but never the true number; the human
 * bridges the gap and [approve] carries the chosen number.
 */
class WebLoginClient(private val http: HttpTransport, private val rpBase: String) {
    private fun trimr(s: String) = s.trimEnd('/')

    class Created(val id: String, val qr: String)

    /**
     * A number-matching login as the INITIATING surface sees it: the login [id],
     * its [qr] (the same opaque tuple as v1), and the [matchNumber] this surface
     * must display for the user to find on their phone.
     */
    class CreatedNumberMatch(val id: String, val qr: String, val matchNumber: Int)

    class Poll(val status: String, val token: String?, val user: String?)

    /** Browser: start a login. */
    fun createLogin(): Created {
        val resp = http.post(trimr(rpBase) + "/login")
        require(resp.status == 200) { "weblogin: create: HTTP ${resp.status}" }
        val o = MiniJson.parseObject(resp.body.decodeToString())
        return Created(o["id"] as String, o["qr"] as String)
    }

    /**
     * Browser (initiating surface): start a **number-matching (v2)** login. The
     * response carries the true match number for this surface to display — the phone
     * never receives it. Used for push logins, where nothing is scanned, to restore
     * the QR's origin-binding.
     */
    fun createNumberMatchLogin(): CreatedNumberMatch {
        val resp = http.post(trimr(rpBase) + "/login?mode=number-match")
        require(resp.status == 200) { "weblogin: create v2: HTTP ${resp.status}" }
        val o = MiniJson.parseObject(resp.body.decodeToString())
        val match = (o["match_number"] as? Long)
            ?: throw IllegalStateException("weblogin: v2 create returned no match_number")
        return CreatedNumberMatch(o["id"] as String, o["qr"] as String, match.toInt())
    }

    /** Browser: poll a login's status (and token once approved). */
    fun poll(id: String): Poll {
        val resp = http.get(trimr(rpBase) + "/login/" + id)
        require(resp.status == 200) { "weblogin: poll: HTTP ${resp.status}" }
        val o = MiniJson.parseObject(resp.body.decodeToString())
        return Poll(o["status"] as String, o["token"] as? String, o["user"] as? String)
    }

    /**
     * Device: fetch the exact challenge to sign (the RP is the source of truth). For
     * a v2 login the challenge carries the display-only [WebLogin.Challenge.candidates]
     * (the true number is DELIBERATELY absent — the phone must not learn which
     * candidate is right).
     */
    fun fetchChallenge(id: String): WebLogin.Challenge {
        val resp = http.get(trimr(rpBase) + "/login/" + id + "/challenge")
        // A reached-but-refused RP throws the typed exception so the flow layer can tell it
        // apart from a transport failure (which arrives as the platform transport's own throw).
        if (resp.status != 200) throw WebLoginHttpException(resp.status, "fetch challenge")
        val o = MiniJson.parseObject(resp.body.decodeToString())

        @Suppress("UNCHECKED_CAST")
        val candidates = (o["candidates"] as? List<Long>)?.map { it.toInt() } ?: emptyList()
        return WebLogin.Challenge(
            id = o["id"] as String,
            nonce = Base64Url.decode(o["nonce"] as String),
            audience = o["audience"] as String,
            expiresAt = o["expires_at"] as Long,
            candidates = candidates,
        )
    }

    /**
     * Device: submit a signed assertion to approve the login. A v2 (number-matching)
     * assertion carries the chosen `match_number`; a v1 one omits it (matching Go's
     * `omitempty`), so the same call serves both.
     */
    fun approve(id: String, assertion: WebLogin.Assertion) {
        // Field order follows void-which-binds-go's Assertion struct (cert, ops, sig, match_number).
        val fields = buildList<Pair<String, Any>> {
            add("cert" to assertion.cert)
            if (assertion.ops.isNotEmpty()) add("ops" to assertion.ops)
            add("sig" to assertion.sig)
            assertion.matchNumber?.let { add("match_number" to it) }
        }
        val body = MiniJson.encodeObject(fields).encodeToByteArray()
        val resp = http.post(trimr(rpBase) + "/login/" + id + "/approve", body, "application/json")
        require(resp.status == 204) { "weblogin: approve refused: HTTP ${resp.status}" }
    }
}
