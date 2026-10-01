package one.rarebit.cruciform.platform

import one.rarebit.cruciform.BuildConfig
import java.net.URI
import java.net.URISyntaxException

/**
 * The pairing-relay base URL: its default and its validation. Pure Kotlin (no Android
 * types) so the rules are unit-tested on the JVM; [RelaySettings] is the persisted
 * half. The library appends `/v1/sessions…` to whatever base it is handed
 * ([one.rarebit.voidwhichbinds.net.RelayClient]), so the base is the mount point of a
 * relay, e.g. `https://relay.example.com/pair` (a heyarr node's `RelayPrefix`).
 */
object RelayConfig {

    /**
     * The relay a fresh install pairs through, or `""` when this build carries none.
     * It is a BUILD-TIME value (`BuildConfig.DEFAULT_RELAY_URL`, from the
     * `CRUCIFORM_DEFAULT_RELAY` / `cruciformDefaultRelay` setting — see
     * `androidApp/build.gradle.kts`), never a committed constant: a private LAN
     * endpoint must not ship baked into the APK. With no default the user sets one in
     * Settings → "Pairing relay", and "Add a device" says so instead of dialling `""`.
     * The relay only ever carries the encrypted pairing transcript, so it leaks
     * nothing either way (the SAS compare is what authenticates the pairing).
     */
    val DEFAULT_RELAY: String = BuildConfig.DEFAULT_RELAY_URL.trim()

    /** True when this build ships a default relay (see [DEFAULT_RELAY]). */
    val hasDefault: Boolean get() = DEFAULT_RELAY.isNotEmpty()

    /** What a good value looks like, for validation messages (never a real endpoint). */
    const val EXAMPLE_RELAY = "https://relay.example.com/pair"

    /**
     * What [validate] decided about a typed URL. Shared by every endpoint field in
     * Settings (the relay and [NotifyConfig]'s push plane), because the rules are the
     * same rules — an absolute http/https base with a host and nothing else.
     */
    sealed interface Validation {
        /** [url] is the normalised base to persist (trimmed, no trailing slash). */
        data class Valid(val url: String) : Validation

        /** Human-readable reason, shown inline under the field. */
        data class Invalid(val reason: String) : Validation
    }

    /**
     * Accept an absolute `http`/`https` URL with a host and no query/fragment/userinfo;
     * normalise by trimming whitespace and trailing slashes (the relay client joins
     * with its own `/v1/...`, and a `base//v1` would 404). Blank input is invalid —
     * "use the default" is [RelaySettings.reset], not an empty string.
     */
    fun validate(input: String): Validation = validateBase(input, noun = "relay", example = EXAMPLE_RELAY)

    /**
     * The shared endpoint-base rules, parameterised only by how the field names itself
     * in its messages ([noun]) and what a good value looks like ([example]). Every
     * Settings endpoint field validates through here — the relay above and the push
     * plane in [NotifyConfig] — so there is one definition of "an acceptable base URL"
     * rather than one per field that can drift apart.
     */
    fun validateBase(input: String, noun: String, example: String): Validation {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return Validation.Invalid("Enter the $noun URL, or reset to the default.")
        val uri = try {
            URI(trimmed)
        } catch (e: URISyntaxException) {
            return Validation.Invalid("Not a valid URL.")
        }
        val scheme = uri.scheme?.lowercase()
        if (scheme != "http" && scheme != "https") {
            return Validation.Invalid("The URL must start with http:// or https://.")
        }
        if (uri.host.isNullOrBlank() || uri.rawAuthority.isNullOrBlank()) {
            return Validation.Invalid("The URL needs a host, like $example.")
        }
        if (uri.rawUserInfo != null) return Validation.Invalid("The URL can't carry credentials.")
        if (uri.rawQuery != null || uri.rawFragment != null) {
            return Validation.Invalid("Enter just the $noun base — no ?query or #fragment.")
        }
        return Validation.Valid(trimmed.trimEnd('/'))
    }

    /** `validate(input)` as a nullable normalised URL, for callers that only need go/no-go. */
    fun normalizeOrNull(input: String): String? = (validate(input) as? Validation.Valid)?.url
}
