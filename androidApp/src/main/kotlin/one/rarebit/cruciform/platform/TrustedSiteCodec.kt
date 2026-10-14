package one.rarebit.cruciform.platform

import one.rarebit.cruciform.domain.SiteAccent
import one.rarebit.cruciform.domain.TrustedSite

/**
 * The on-disk shape of the trusted-sites list ([IdentityStore.KEY_SITES]): one header
 * line, then one row per site, fields separated by the ASCII unit separator (U+001F).
 *
 * Pure Kotlin so the round trip is unit-tested on the JVM. The header exists because
 * the first shipped encoding (through app-v0.7.2) joined fields with the EMPTY string,
 * which wrote every row as one undelimited blob and read it back one character at a
 * time — a site titled "h" with the subtitle "e · y" for `heyarr.home.example`.
 * Those rows carry no separators, so they cannot be recovered: a value without the
 * header decodes to an empty list and the next approval rewrites it in this format.
 * The unit separator cannot appear in a host, an app name, a relative-time label or an
 * enum name, so a value never needs escaping.
 */
object TrustedSiteCodec {
    const val HEADER = "trusted-sites/v1"
    const val FIELD = '\u001F'
    private const val ROW = '\n'
    private const val FIELDS = 5

    fun encode(sites: List<TrustedSite>): String = buildString {
        append(HEADER)
        for (s in sites) {
            append(ROW)
            append(listOf(s.id, s.domain, s.appName, s.lastUsed, s.accent.name).joinToString(FIELD.toString()))
        }
    }

    fun decode(raw: String?): List<TrustedSite> {
        if (raw.isNullOrBlank()) return emptyList()
        val lines = raw.split(ROW)
        if (lines.first() != HEADER) return emptyList() // pre-v1 (undelimited) — see the class doc
        return lines.drop(1).filter { it.isNotBlank() }.mapNotNull { line ->
            val p = line.split(FIELD)
            if (p.size != FIELDS || p[0].isEmpty()) {
                null
            } else {
                TrustedSite(
                    id = p[0],
                    domain = p[1],
                    appName = p[2],
                    lastUsed = p[3],
                    accent = runCatching { SiteAccent.valueOf(p[4]) }.getOrDefault(SiteAccent.BLUE),
                )
            }
        }
    }
}
