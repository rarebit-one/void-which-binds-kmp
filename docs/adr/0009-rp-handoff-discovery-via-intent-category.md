# 0009. RP same-phone handoff targets discover themselves via a shared intent category

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-04
**Relates to:** ADR-0006 (the reverse same-phone handoff and its hard-coded registry),
ADR-0008 (the same-phone one-tap return leg), ADR-0003 (the RP → authenticator
`voidbind:` deep link). Closes voidbind-kmp #39.

## Context

ADR-0006's "Send to `<app>` on this phone" list was a **hard-coded registry**
(`RpPairHandoff.KNOWN`: `heyarr-mobile://pair`, `allthing://pair`) backed by one manifest
`<queries>` entry **per RP scheme**. Two costs followed:

1. **A new relying party needs a Cruciform release.** The list is compiled into the
   authenticator, so any RP that wants a one-tap handoff button must wait for us to ship a
   new `KNOWN` row and a new `<queries>` entry — the RPs cannot advertise themselves.
2. **The visibility query must exactly mirror each RP's filter.** We already shipped one
   bug here (0.5.1/0.5.2): a scheme-only `<queries>` entry does not grant visibility to an
   RP's `scheme://pair` (host-bearing) filter, so the button silently never appeared. Every
   RP multiplies that coupling.

ADR-0006 itself flagged the fix under "What would make us revisit": *"A discovery mechanism
(an RP advertising its pair callback via `<meta-data>`) if the registry grows past a
handful of first-party apps."* This is that mechanism.

## Decision

1. **A shared intent category, `one.rarebit.voidbind.category.RP_HANDOFF`**, is the
   contract. An RP that can receive a same-phone Voidbind pairing handoff declares a
   **data-less** `ACTION_VIEW` intent-filter carrying this category, plus a `<meta-data>`
   naming its pair scheme:

   ```xml
   <!-- discovery: advertise same-phone Voidbind handoff to Cruciform -->
   <intent-filter>
       <action android:name="android.intent.action.VIEW" />
       <category android:name="one.rarebit.voidbind.category.RP_HANDOFF" />
   </intent-filter>
   <meta-data
       android:name="one.rarebit.voidbind.rp.pair_scheme"
       android:value="heyarr-mobile" />
   ```

   This sits **alongside** the RP's existing `scheme://pair` VIEW filter (unchanged — it is
   what actually receives `scheme://pair?invite=…`). The advertisement declares capability;
   the handoff filter receives the invite.

2. **Cruciform discovers targets by querying `PackageManager`** for a VIEW intent carrying
   the category, `GET_META_DATA` set:

   ```kotlin
   val probe = Intent(Intent.ACTION_VIEW).addCategory(CATEGORY_RP_HANDOFF)
   pm.queryIntentActivities(probe, PackageManager.GET_META_DATA)
   ```

   For each resolved activity it reads the **label** from the activity's `android:label`
   (`ResolveInfo.loadLabel`) and the **scheme** from the `META_PAIR_SCHEME` meta-data, then
   maps `(label, scheme)` → `RpPairTarget(appName = label, callbackBase = "<scheme>://pair")`
   (`RpPairHandoff.targetsFrom`). One generic `<queries>` entry — the same category —
   replaces the per-scheme entries and grants Cruciform visibility to **every** advertising
   RP.

3. **Why a data-less discovery filter + a meta-data scheme, and not the category on the
   `scheme://pair` filter.** Android intent matching refuses a data-bearing filter when the
   probing intent has no data, and a data-less filter when the intent *has* data — so a
   generic probe (which cannot know the RP's scheme in advance; that is the whole point)
   can only match a **data-less** filter. And because `queryIntentActivities` returns the
   resolved activity but not its *other* filters' `<data>`, the scheme Cruciform must fire
   is not recoverable from the resolution — so the RP states it explicitly in `<meta-data>`.
   This is the robust pair: a data-less advertisement for discovery, a meta-data value for
   the scheme, the real `scheme://pair` filter for receipt.

4. **`RpPairHandoff.uriFor` and the wire are unchanged.** Only the *source* of the target
   list changes — from the compiled `KNOWN` to the runtime query. The invite still travels
   as one percent-encoded `<scheme>://pair?invite=…` value (byte-identical to the QR), and
   the one-tap `cruciform://pair-joined` / `<scheme>://pair-done` contract (ADR-0008) is
   untouched: the return leg already built its callback from the *resolved* scheme, so it
   now reads that scheme from the matching advert instead of the `KNOWN` row.

5. **Graceful fallback.** Nothing resolving → an empty target list → the QR and Sharesheet
   paths only, exactly as when no RP is installed. An advertising activity with no
   `META_PAIR_SCHEME` (or a blank one, or the `voidbind` scheme — ours, which would loop) is
   dropped, never shown as a broken button.

## Consequences

- **A new relying party ships with zero Cruciform changes.** It adds the category
  intent-filter + the meta-data to its own manifest and appears as a "Send to `<app>`"
  button the next time the user mints an invite. The registry is gone.
- **One `<queries>` line, one category, no per-scheme coupling.** The 0.5.1/0.5.2
  scheme/host-mismatch class of bug cannot recur: there is nothing per-RP to keep in step.
- **The security posture is unchanged.** Discovery only decides which buttons appear and
  what they are labelled. A malicious app can advertise the category and receive an invite
  the user *explicitly sent it* — exactly the ADR-0006 position — and the SAS comparison on
  Cruciform (ADR-0006 §4, ADR-0008's relay cross-check) is still what refuses a substituted
  peer. Nothing is signed on the strength of an advertisement.
- **Label spoofing is cosmetic.** An app can advertise any `android:label`; the worst case
  is a mislabelled button for an invite the user chose to send. The device-key + SAS check
  against the relay is unaffected, and (as in ADR-0008) an unidentified caller whose key and
  SAS match is still a match.

## What would make us revisit

- **Verified App Links** (an `https` host the RP proves it owns) for the pair callback,
  once RPs have a domain — then discovery could prefer verified hosts and close even the
  "user sent the invite to a squatting app" window.
- **A signature/allowlist filter** on discovery (e.g. only advertisements from apps sharing
  a signing identity, or on an explicit user-approved list) if third-party RPs ever appear
  and the "any app can advertise" surface stops being acceptable.
