package one.rarebit.cruciform.handoff

/**
 * The **reverse** same-device handoff (ADR-0006, discovery per ADR-0009): this
 * authenticator holds a pairing invite it just minted (Settings → Devices → "Add a
 * device") and the NEW device is a relying-party app on the SAME phone — heyarr-mobile,
 * All Thing — which cannot scan our screen. ADR-0003 already lets an RP open us with a
 * `void-which-binds:` link; this is the mirror: we open the RP with its own **pair-callback**
 * URI carrying the invite.
 *
 *     heyarr-mobile://pair?invite=<percent-encoded void-which-binds:pair?… tuple>
 *     allthing://pair?invite=<…>
 *
 * The scheme is the RP's, never `void-which-binds:` — that one is ours, and firing it would
 * only loop back into this app. The invite tuple travels verbatim (byte-identical to
 * the QR), so the RP feeds it to the same `Invite.decode` a scan would; nothing here
 * is a new wire format.
 *
 * The list of targets is **discovered**, not hard-coded (#39 / ADR-0009): an RP
 * advertises itself with the shared [CATEGORY_RP_HANDOFF] intent category and a
 * [META_PAIR_SCHEME] `<meta-data>`; Cruciform's [RpPairLauncher] resolves those and
 * this object maps each resolved advert to a target. A button appears only for a
 * target that actually resolves on the phone — unknown or absent apps get the
 * Sharesheet fallback.
 *
 * Pure Kotlin (no android.* imports) so the URI/label/scheme logic is unit-tested on
 * the JVM; the Android `PackageManager` query that produces the [RpHandoffAdvert]s
 * lives in [RpPairLauncher].
 */
data class RpPairTarget(
    /** The human name on the button: "Send to heyarr on this phone". */
    val appName: String,
    /** The RP's pair-callback base, `scheme://host` — the app registers a VIEW filter for it. */
    val callbackBase: String,
) {
    val scheme: String get() = callbackBase.substringBefore(':')
}

/**
 * One relying-party app's self-advertisement, exactly as Cruciform's `PackageManager`
 * query resolved it: the package Android reported, the launcher [label] to show on the
 * button, and the [pairScheme] the app declared via its [RpPairHandoff.META_PAIR_SCHEME]
 * `<meta-data>`. Pure data so the mapping to targets/identity below is JVM-tested with
 * no Android runtime; [RpPairLauncher.adverts] is the sole producer on-device.
 */
data class RpHandoffAdvert(val packageName: String, val label: String?, val pairScheme: String?)

object RpPairHandoff {

    /** The query key the RP reads the invite from. */
    const val INVITE = "invite"

    /**
     * The shared intent category an RP adds to a **data-less** `ACTION_VIEW`
     * intent-filter to advertise "I can receive a same-phone Void-Which-Binds pairing handoff"
     * (ADR-0009). Cruciform discovers RPs by querying `PackageManager` for a VIEW intent
     * carrying this category; a data-less probe cannot match a `scheme://pair` filter
     * (Android intent matching refuses a data-bearing filter when the intent has no
     * data), so the RP declares a dedicated data-less filter for discovery alongside its
     * real `scheme://pair` handoff filter.
     */
    const val CATEGORY_RP_HANDOFF = "one.rarebit.voidwhichbinds.category.RP_HANDOFF"

    /**
     * The `<meta-data>` key on the RP's advertised activity carrying its pair scheme
     * (ADR-0009). The discovery query returns the resolved activity but not the OTHER
     * filters' data, so the scheme Cruciform fires — `<scheme>://pair` — is read from
     * this meta-data, and the button label from the activity's `android:label`.
     */
    const val META_PAIR_SCHEME = "one.rarebit.voidwhichbinds.rp.pair_scheme"

    /** The host every RP pair callback uses: `<scheme>://pair`. */
    const val PAIR_HOST = "pair"

    /** Schemes an RP may not advertise as its pair callback: ours, and gen1's. */
    private val REFUSED_SCHEMES = setOf("void-which-binds", "voidbind")

    /**
     * Turn one RP self-advert into a [RpPairTarget], or null when it is unusable:
     * no scheme declared, a blank/whitespace scheme, the `void-which-binds` scheme (ours —
     * firing it would loop straight back into Cruciform), or the retired gen1 `voidbind`
     * scheme (it would hand a gen2 invite to a gen1 authenticator; ADR-0022). The scheme is lower-cased
     * (schemes are case-insensitive; we render one canonically); the label falls back to
     * a generic name so a button still has text.
     */
    fun targetFrom(advert: RpHandoffAdvert): RpPairTarget? {
        val scheme = advert.pairScheme?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return null
        if (scheme in REFUSED_SCHEMES) return null
        val label = advert.label?.trim()?.takeIf { it.isNotEmpty() } ?: "this app"
        return RpPairTarget(appName = label, callbackBase = "$scheme://$PAIR_HOST")
    }

    /**
     * The "Send to `<app>` on this phone" targets, one per usable advert, de-duplicated
     * by scheme (first advert wins) and stably ordered by label so the button order does
     * not jitter between queries. An empty result → the QR / Sharesheet path only.
     */
    fun targetsFrom(adverts: List<RpHandoffAdvert>): List<RpPairTarget> = adverts.mapNotNull(::targetFrom)
        .distinctBy { it.scheme }
        .sortedBy { it.appName.lowercase() }

    /**
     * The advert whose package is [callerPackage] — the return leg of the same-phone
     * one-tap path (ADR-0008): a `cruciform://pair-joined` callback names the app by the
     * package Android reports, and this maps that package back to its advertised scheme +
     * label so the `<scheme>://pair-done` landing can be addressed and the sheet labelled.
     * Null when the caller did not advertise (an unknown app → a generic label upstream,
     * never a borrowed one).
     */
    fun advertForPackage(adverts: List<RpHandoffAdvert>, callerPackage: String?): RpHandoffAdvert? =
        callerPackage?.takeIf { it.isNotBlank() }?.let { p -> adverts.firstOrNull { it.packageName == p } }

    /**
     * Build the URI that hands [inviteTuple] (the exact `void-which-binds:pair?…` string the QR
     * shows) to [target]. The tuple is percent-encoded as a single query value so its
     * own `?`/`&`/`=` survive; the RP decodes it back to the byte-identical invite.
     * Refuses anything that is not a pair invite — an RP must never receive a login
     * tuple through this door.
     */
    fun uriFor(target: RpPairTarget, inviteTuple: String): String {
        require(inviteTuple.startsWith("void-which-binds:pair?")) { "not a void-which-binds pairing invite" }
        return "${target.callbackBase}?$INVITE=${percentEncode(inviteTuple)}"
    }

    /**
     * RFC 3986 percent-encoding of a query VALUE: keep the unreserved set
     * `A-Za-z0-9-_.~`, encode every other byte (UTF-8) as uppercase `%XX`. Deliberately
     * not Go's `url.QueryEscape` (which writes a space as `+`) so the RP can decode it
     * with any standard percent-decoder without a `+` ambiguity.
     */
    fun percentEncode(s: String): String {
        val bytes = s.encodeToByteArray()
        val out = StringBuilder(bytes.size * 3)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            val ch = c.toChar()
            if (ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '_' || ch == '.' ||
                ch == '~'
            ) {
                out.append(ch)
            } else {
                out.append('%').append(HEX[c ushr 4]).append(HEX[c and 0x0F])
            }
        }
        return out.toString()
    }

    private val HEX = "0123456789ABCDEF".toCharArray()
}
