package one.rarebit.voidwhichbinds.policy

/**
 * Per-RP **approval policy** — how much consent friction a known relying party gets
 * on the web-login approval sheet. This is policy/consent state that sits AROUND the
 * existing hardware-gated signature; it never changes the crypto path. Every login
 * still produces the same biometric-gated Ed25519 assertion (see
 * [one.rarebit.voidwhichbinds.flow.LoginApproval]) — the policy only decides whether the
 * app shows the full consent review or a streamlined confirmation for a site the
 * user already trusts.
 *
 * Two states:
 *  - [AlwaysAsk] — show the full consent sheet every time. This is the state of a
 *    brand-new RP, and the state a user can pin to force review forever.
 *  - [TrustedTofu] — **trust-on-first-use**: after one successful approval the RP is
 *    remembered as trusted and later logins may be streamlined.
 */
enum class ApprovalPolicy {
    /** Show the full consent sheet on every login (the default, and the user-pinned override). */
    AlwaysAsk,

    /** Trust-on-first-use: the RP was approved once and is remembered as trusted. */
    TrustedTofu,
}

/**
 * The remembered policy for one relying party, keyed by [rp] (the app's stable RP
 * identifier — its host). A brand-new RP has NO [SitePolicy] at all; the absence is
 * itself "always ask, never yet trusted". Persist this via a [SitePolicyStore].
 *
 * [pinnedAlwaysAsk] is the user override: when true, a successful login must NOT
 * silently upgrade the site to [ApprovalPolicy.TrustedTofu] — the user asked to be
 * prompted every time, and trust-on-first-use must respect that. [firstTrustedAt] is
 * the unix-seconds timestamp of the approval that first trusted the site (null while
 * it is still [ApprovalPolicy.AlwaysAsk]).
 */
data class SitePolicy(
    val rp: String,
    val policy: ApprovalPolicy,
    val pinnedAlwaysAsk: Boolean = false,
    val firstTrustedAt: Long? = null,
)

/**
 * The pure state-machine transitions for [SitePolicy]. No I/O, no clock of its own —
 * time is passed in, persistence is a separate seam ([SitePolicyStore]). Kept as a
 * standalone object so the TOFU rules are unit-testable without any store.
 */
object ApprovalPolicyMachine {

    /**
     * Whether the full consent sheet must be shown for the RP whose current policy is
     * [current] (null = never seen). True for a brand-new or [ApprovalPolicy.AlwaysAsk]
     * site; false only once the site is [ApprovalPolicy.TrustedTofu].
     */
    fun requiresConsentSheet(current: SitePolicy?): Boolean =
        current == null || current.policy == ApprovalPolicy.AlwaysAsk

    /**
     * Apply trust-on-first-use after a **successful** approval at [rp] (at unix-seconds
     * [at]). A brand-new site becomes [ApprovalPolicy.TrustedTofu]; an already-trusted
     * site is unchanged (its original [SitePolicy.firstTrustedAt] is preserved). A site
     * the user [pinnedAlwaysAsk] stays [ApprovalPolicy.AlwaysAsk] — the pin wins over TOFU.
     */
    fun onSuccessfulApproval(current: SitePolicy?, rp: String, at: Long): SitePolicy = when {
        current == null ->
            SitePolicy(rp, ApprovalPolicy.TrustedTofu, pinnedAlwaysAsk = false, firstTrustedAt = at)

        current.pinnedAlwaysAsk ->
            current.copy(rp = rp)

        // honour the user's "always ask"; do not auto-trust
        current.policy == ApprovalPolicy.TrustedTofu ->
            current.copy(rp = rp)

        // already trusted; keep the original firstTrustedAt
        else ->
            current.copy(policy = ApprovalPolicy.TrustedTofu, firstTrustedAt = current.firstTrustedAt ?: at)
    }

    /**
     * The user explicitly chooses "always ask" for [rp]: pin it so future TOFU cannot
     * silently re-trust it, and force the full sheet from now on.
     */
    fun pinAlwaysAsk(rp: String): SitePolicy =
        SitePolicy(rp, ApprovalPolicy.AlwaysAsk, pinnedAlwaysAsk = true, firstTrustedAt = null)

    /**
     * The user explicitly chooses to trust [rp] (at unix-seconds [at]): set it
     * [ApprovalPolicy.TrustedTofu] and clear any always-ask pin.
     */
    fun trust(current: SitePolicy?, rp: String, at: Long): SitePolicy = SitePolicy(
        rp,
        ApprovalPolicy.TrustedTofu,
        pinnedAlwaysAsk = false,
        firstTrustedAt = current?.firstTrustedAt ?: at,
    )
}
