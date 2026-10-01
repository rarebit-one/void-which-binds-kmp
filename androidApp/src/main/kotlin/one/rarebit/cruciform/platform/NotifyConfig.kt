package one.rarebit.cruciform.platform

import one.rarebit.cruciform.BuildConfig

/**
 * The **push/wake plane** base URL: its default and its validation — the notify
 * half of what [RelayConfig] is for pairing. Pure Kotlin (no Android types) so the
 * rules are unit-tested on the JVM; [NotifySettings] is the persisted half.
 *
 * The library appends `/v1/subscriptions` to whatever base it is handed
 * ([one.rarebit.voidwhichbinds.net.NotifyClient]), so this is the plane's mount point.
 *
 * The plane is a **wake channel, not a crypto path**: this phone registers a public
 * ntfy topic URL with it and is later woken by an opaque login tuple. No key
 * material, no challenge and no match number ever crosses it — the login is still
 * pulled from the relying party over its own transport and signed hardware-gated.
 */
object NotifyConfig {

    /**
     * The plane a fresh install registers its wake endpoint with, or `""` when this
     * build carries none. A BUILD-TIME value (`BuildConfig.DEFAULT_NOTIFY_URL`, from the
     * `CRUCIFORM_DEFAULT_NOTIFY` / `cruciformDefaultNotify` setting — see
     * `androidApp/build.gradle.kts`), never a committed constant: a private LAN
     * endpoint must not ship baked into the APK. With no default (and no Settings
     * override) push registration is simply skipped — scanned-QR login is unaffected.
     */
    val DEFAULT_NOTIFY: String = BuildConfig.DEFAULT_NOTIFY_URL.trim()

    /** True when this build ships a default plane (see [DEFAULT_NOTIFY]). */
    val hasDefault: Boolean get() = DEFAULT_NOTIFY.isNotEmpty()

    /** What a good value looks like, for validation messages (never a real endpoint). */
    const val EXAMPLE_NOTIFY = "https://notify.example.com"

    /**
     * The same endpoint-base rules the relay field uses ([RelayConfig.validateBase]) —
     * an absolute http/https base with a host and no query/fragment/userinfo, trimmed
     * of trailing slashes so the client's `/v1/...` join cannot produce `base//v1`.
     */
    fun validate(input: String): RelayConfig.Validation =
        RelayConfig.validateBase(input, noun = "push plane", example = EXAMPLE_NOTIFY)

    /** `validate(input)` as a nullable normalised URL, for callers that only need go/no-go. */
    fun normalizeOrNull(input: String): String? = (validate(input) as? RelayConfig.Validation.Valid)?.url
}
