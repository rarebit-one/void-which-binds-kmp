# Device testing — proving the hardware keystore

The keystore's acceptance is **device-tested, not CI**: a StrongBox secure element
and a Secure Enclave do not exist on an emulator or the iOS Simulator, so the
non-extractability and biometric properties can only be shown on real hardware.
This is the runbook, plus the map of what still has to be built to reach the full
"app pairs + web QR-login with the hardware key" acceptance.

## Status

| Piece | State |
|---|---|
| Crypto decision (ADR-0001) | ✅ resolved + recorded |
| `Ed25519Engine` (software, multiplatform) | ✅ done, JVM round-trip tested |
| Pairing/cert wire reconciled to void-which-binds-go **v2** | ✅ done + merged (dual-key commit, 7-digit SAS) |
| `DeviceKeyStore` JVM actual (software) | ✅ done |
| `DeviceKeyStore` Android actual (StrongBox-sealed) | ✅ compiles; **needs a device to prove non-extractability** |
| `DeviceKeyStore` iOS actual (SE-sealed) | ✅ compiles; **needs a device** |
| Swift `SecureEnclaveSealer` implementation | ✅ written (`iosApp/Voidbind/SecureEnclaveSealer.swift`); **needs Xcode + a device** |
| `UserIdentity` / `Enrolment` / `LoginQr` / flow coordinators (commonMain) | ✅ done, unit-tested + cross-language proven vs live void-which-binds-go |
| `VoidWhichBinds.xcframework` export | ✅ done (`assembleVoidWhichBindsXCFramework`) |
| Android app shell (Compose) | 🚧 in progress (peer session — `androidApp/`) |
| iOS app shell (SwiftUI) | 🚧 scaffold (`iosApp/`); full screen set on-device |
| Live web QR-login vs All Thing / heyarr | ⏳ device test (below) |
| Same-device app-to-app deep link (`void-which-binds:login?…` from an RP app) | ✅ approval sheet proven on-device via `adb am start` against a live heyarr node (Test 5) |
| Reverse same-device handoff (ADR-0006): "Send to `<app>` on this phone" from the invite screen | ✅ buttons resolve per installed RP; **end-to-end (RP joins → SAS on both apps → confirm here) needs the human finger (Test 6)** |
| Membership op-set (ADR-0005): any member adds the next; Devices list + Remove | ✅ library proven vs live void-which-binds-go (14/14 vectors, phone→phone through the Go relay, Go RP honours `ops`); **on-device: upgrade-in-place + Devices list proven; a real second-phone pair/remove needs a second phone (Test 4b)** |
| Recovery shares (SLIP-39, void-which-binds-go ADR-0011): restore from 2-of-3 shares, typed; split on the phone | ✅ library passes Trezor's 45 vectors + combines Go-made shares (JVM); **on-device restore from Go-made shares: Test 2e; split on the phone and restore elsewhere: Test 2f** |

The commonMain "device brain" (identity derivation, self-enrolment, the
`LoginApproval` / `DevicePairing` / `DeviceAuthorization` coordinators, the QR
wire) is done and **cross-language proven against a live void-which-binds-go**
(`CoordinatorGoInteropTest`: a coordinator-driven login on the real Go RP + the
pairing coordinators through the real Go relay). What remains is genuinely
device-bound: the Secure Enclave / StrongBox properties and the biometric gate.

## What you need

- A **physical Android device with a StrongBox** secure element (Pixel 3+ or any
  device advertising `FEATURE_STRONGBOX_KEYSTORE`), with a screen lock + a
  fingerprint/face enrolled.
- A **physical iPhone with a Secure Enclave** (any Face/Touch ID iPhone), with a
  passcode + biometric enrolled.
- A reachable **All Thing** (or heyarr) instance to log in against, over the VPN
  or on the LAN. Standing one up locally: build the `allthing` binary and run
  `allthing serve` behind a bearer token; the QR-login endpoint is the target the
  app signs a challenge for.

## Test 1 — the device key is non-extractable in secure hardware

**Android**
1. In the app, provision a device key: `DeviceKeyStore.getOrCreate("device")`
   (after `VoidbindAndroid.init(applicationContext)`), authenticating at the
   `BiometricPrompt` when asked.
2. Confirm the wrapping key reports StrongBox: read its `KeyInfo`
   (`KeyFactory.getKeySpec(..., KeyInfo::class)`) and assert
   `getSecurityLevel() == SECURITY_LEVEL_STRONGBOX` (API 31+). If the device has
   no StrongBox it falls back to TEE — note which.
3. Prove non-extractability: there is no API that returns the AES wrapping key or
   the plaintext seed at rest. Inspect `filesDir/void-which-binds/device.key` — it holds
   only the **sealed** ciphertext + IV + the (public) Ed25519 key. The seed never
   appears there.
4. Prove use is gated: lock the device, wait past the 30-second auth window, and
   call `sign(...)` — it must throw `AuthenticationRequiredException`. Authenticate
   and retry — it must produce a 64-byte signature.

**iOS**
1. Provision with `DeviceKeyStore.getOrCreate("device")` after
   `VoidbindIos.shared.doInit(sealer:)` (the app builds `VoidbindEngine()`, which
   injects the Swift `SecureEnclaveSealer`).
2. The Secure-Enclave P-256 key is created with `kSecAttrTokenIDSecureEnclave` +
   access control `.privateKeyUsage`/`.biometryCurrentSet` — the private key is
   non-extractable by construction (Apple never returns SE key material).
3. Call `sign(...)`: iOS must present Face/Touch ID (the SE unseal), and only then
   return a signature. Cancel the prompt — signing must fail, not proceed.

## Test 2 — onboarding: create / restore an identity on-device

Drives `UserIdentity` + `Enrolment` through the app engine (`OnboardingView` on
iOS; the Android onboarding screens).
1. **Create**: tap "Create a new identity". The app calls `UserIdentity.create()`,
   provisions the device key (biometric fires on first `DeviceKeyStore.getOrCreate`),
   and `Enrolment.selfEnrol`s. A second, **strong-biometric-only** prompt ("Keep a
   recovery copy on this phone") then decides whether the phone keeps a sealed copy.
   Assert the recovery secret is shown (`void-which-binds1…`) with **no copy button**, and that
   the backup screen says whether the phone kept a copy. The identity is provisioned
   before the backup screen appears (confirming the backup is Phase 1 of
   void-which-binds-go#52).
2. **Restore**: reinstall the app (or use a second device), tap "Restore", type the
   secret **exactly as grouped on screen, spaces included**. Assert the reconstructed
   `userId` **equals** the original (recovery restores the SAME pinned identity,
   offline), and that a single mistyped character is rejected loudly (the bech32m
   checksum) rather than yielding a different identity.
3. **The kept copy is behind a strong biometric, not the PIN.** Settings → Recovery
   backup must prompt for a fingerprint/face with **no "Use PIN" option**. On a phone
   with no fingerprint enrolled, it must refuse with the "PIN can't authorise it"
   message. Then enrol a **new** fingerprint in system settings and open Recovery
   backup again: the keystore has destroyed the copy, so the app says it is gone and
   points at the written secret, and the Recovery row disappears on the next launch.
4. **An older install migrates.** Install the previous release, create an identity,
   upgrade to this build, and open Recovery backup once (fingerprint): the copy moves
   under the strong key. The migration is only observable with `adb shell dumpsys
   keystore` / a keystore listing: `voidbind.secret.wrap.recovery` is gone and
   `voidbind.secret.wrap-strong.recovery` exists.

## Test 2c — prove the backup; remove the phone's copy (void-which-binds-go ADR-0010)

1. **Confirm on create.** After "I've saved it", the app asks for three random groups
   (never groups 1–2) from what you wrote. A wrong group is named and nothing is
   recorded. The right groups, in any case, finish onboarding. "Not now" also
   finishes, but Home then shows an amber **Check your recovery secret** card until
   a check passes.
2. **Drill.** Settings → **Test recovery secret**: type the whole written secret,
   spaces and all. On a match it shows the identity's fingerprint (`XXXX XXXX XXXX
   XXXX`), the same one the Home identity card shows, and the row then reads
   "Checked <date>". Another identity's secret is refused, naming both fingerprints.
   No biometric prompt appears and no op is signed (Settings → Devices is unchanged).
3. **Restore counts as a check.** A Restore-provisioned phone shows no card, and
   Settings reads "Checked <date>".
4. **Remove the copy.** Settings → Recovery → **Remove the copy on this phone**:
   - before any drill, it refuses and points at the drill;
   - before any drill, the refusal dialog is titled **Not yet** (not "Something went
     wrong");
   - after one, it asks for a strong biometric (no PIN option), then the Recovery
     backup, Split into shares and Remove rows disappear;
   - the phone still signs in and renews itself;
   - adding a device from it still works (member-signed); re-admitting a REMOVED
     device now needs the paper (Restore on that device).

## Test 2d — print the recovery sheet; scan it back (void-which-binds-go#52)

The sheet mirrors void-which-binds-go `recovery/sheet` (`void-which-binds recovery sheet --out …`):
the secret as an upper-case QR code (alphanumeric, version 4, medium error
correction), the secret in four-character groups, the fingerprint and user ID, four
numbered instructions, corner cut marks and a 50 mm calibration bar. The app draws it
as a one-page PDF and hands it straight to the print framework; nothing of
Cruciform's is written to disk. The layout is unit-tested (`RecoverySheetTest`); the
print, the paper and the camera are what this test proves.

1. **Print.** On the recovery backup screen (during Create, and from Settings →
   Recovery backup) tap **Print recovery sheet**. The system print dialog opens with
   A4 and black-and-white preselected. Choose a real printer (not "Save as PDF", which
   writes the secret to storage) and print at **100% / actual size**, with any "fit
   to page" option off. Letter paper also works: the card is Letter-safe and the page
   follows the paper chosen in the dialog.
2. **Measure the bar.** With a ruler, the bar under "This bar must measure exactly
   50 mm" must be 50 mm (±0.5 mm), and the QR code 58 mm square including its white
   margin (about 47 mm of modules inside it). If the bar is off, the print was scaled:
   reprint at 100% and note the printer/driver. Compare with the Go sheet for the same
   secret: same groups, same fingerprint (`XXXX XXXX XXXX XXXX`, also on Home), same
   user ID (`ed25519:…`).
3. **Scan into Restore.** On a phone with no identity (or after clearing app data):
   Onboarding → Restore → **Scan recovery sheet**, and point the camera at the code.
   The field fills with the upper-case secret and nothing happens until **Restore
   identity**; the restored identity's fingerprint must equal the sheet's. The general
   scanner (Onboarding → **Add this device**) on the sheet also lands in Restore with
   the field filled.
4. **Scan into the drill.** On an enrolled phone: Settings → **Test recovery secret** →
   **Scan recovery sheet**. The field fills; **Check** shows "It matches this identity:
   <fingerprint>" and the row then reads "Checked <date>". The bottom-bar scanner on
   the sheet opens the same drill, filled. Another identity's sheet is refused, naming
   both fingerprints.
5. **Wrong codes say so.** In the bottom-bar scanner, a non-Voidbind QR (any URL) shows
   "Not a Voidbind code" with **Scan again**, which re-arms the camera. In the Restore /
   drill scanner, a login or pairing QR shows "Not a recovery secret…"; **Type it
   instead** returns to the field.
6. **Nothing lingers.** Screenshots are blocked on the scanner, as on the backup
   screen. After printing, `adb shell run-as one.rarebit.cruciform ls -R cache files`
   shows no PDF. (The print spooler holds its own copy of the job until it completes;
   that is the system's, not the app's.)

## Test 2e — restore from recovery shares (void-which-binds-go ADR-0011)

The shares come from void-which-binds-go, so this also proves the SLIP-39 port against the
Go implementation on real hardware (the JVM tests prove the maths; this proves the
phone's PBKDF2 provider and the typing flow). Use a throwaway secret, or the
identity's own secret on a wiped phone.

1. **Make the shares.** In a void-which-binds-go checkout (ADR-0011 or later), split the
   secret you will restore:
   `echo void-which-binds1… | go run ./cmd/void-which-binds recovery split --secret-file -`. It prints
   the user ID, the fingerprint (`XXXX XXXX XXXX XXXX`) and three 33-word shares, any
   2 of which rebuild it. (`--sheets <dir>` also writes printable sheets.) Note the
   fingerprint.
2. **Reach the screen.** On a phone with no identity (reinstall the app, or use a
   second device), tap **Restore from recovery shares** on the
   welcome screen. Also check the other door: **Restore from a recovery secret** →
   **I have recovery shares instead** lands on the same screen, and Back from it
   returns to the welcome screen.
3. **Refusals, one share at a time.** Type share 1 and tap **Add share**: the screen
   reads "1 of 2 needed" and the field clears for share 2. Then check that each of
   these is refused **inline, naming the share, and not counted** (the count stays
   "1 of 2"):
   - share 1 again ("Share 2 is one you've already entered");
   - share 2 with one word changed ("Share 2 has a mistake");
   - a share from a second `recovery split` of the same secret ("Share 2 is from a
     different set of shares");
   - a truncated share (drop the last word).
   **Start over** clears the count back to "No shares entered yet".
4. **Restore.** Enter any two different shares, in either order: the screen reads "2
   of 2 shares entered: ready to restore". Tap **Restore identity** and approve the
   device-key biometric. Assert Home shows the SAME identity: the fingerprint and
   user ID from step 1 (Settings / the Home identity card), and no "Check your
   recovery secret" card (a restore from shares counts as a check, as in 2c.3).
   Declining the biometric leaves the shares in place with the reason shown; tapping
   **Restore identity** again retries.
5. **Memory only.** Enter one share, rotate the phone: the count survives (the
   ViewModel outlives the rotation). Then enter one share, background the app and
   kill it (`adb shell am kill one.rarebit.cruciform`), reopen: the count is gone, as
   the shares were never saved. Leaving the screen (Back) also forgets them.

## Test 2f — split into shares on the phone; restore from 2 of them elsewhere

The phone splits its kept copy of the recovery secret with the same SLIP-39 profile
as `void-which-binds recovery split` (any 2 of 3, no passphrase), so this proves the split
half on real hardware; Test 2e proved the restore half.

1. **Split.** On a phone that keeps the recovery copy: Settings → Recovery → **Split
   into shares**. It asks for a strong biometric (no PIN option; declining shows
   "Cancelled" and nothing opens). Then "Share 1 of 3 · any 2 restore your identity"
   shows 33 numbered words in two columns. There is no copy button, and a screenshot
   is blocked. Write it down, tap **Next** for shares 2 and 3, then **Done** returns to
   Settings. Back, or leaving mid-way, forgets the shares; splitting again gives a new
   set (shares from different splits don't combine).
2. **Refusals.** On a phone that keeps no copy (removed in 2c.4, or created with the
   biometric prompt declined), the row is absent. If the strong biometric can't be
   used (every fingerprint and face removed since the copy was kept), the split is
   refused in a dialog titled **Not yet** that points at a biometric or the paper.
3. **Restore elsewhere.** On a second phone with no identity (or after clearing app
   data), follow Test 2e.2–2e.4 with any 2 of the 3 shares from step 1. Home must show
   the first phone's fingerprint (`XXXX XXXX XXXX XXXX`) and user ID. Try a second pair
   too (e.g. shares 1 and 3) after clearing data again.
4. **Nothing revoked.** The written recovery secret still passes Settings → **Test
   recovery secret** on the first phone, and Settings → Devices there is unchanged
   (splitting signs nothing).

## Test 2b — membership renewal (a device renews itself before its add lapses)

An add lasts 90 days. Inside the last 30 the device renews itself: silently right
after it signs (a login, authorising a device), or via Home → "Renew now".
Use a build with a shortened `Enrolment.DEFAULT_LIFETIME_SECONDS`, or set the phone's
clock forward (auto-time off) past day 60.
1. Home shows the amber "Renew this device" card; tap **Renew now**. Assert the card
   goes away, and Settings → Devices shows a later "renews by" date for this device.
2. Sign in to an RP after the ORIGINAL add's expiry: the login succeeds, because the
   device now presents its renewal as its credential.
3. Set the clock past day 90 **without** renewing: Home shows "This device has lapsed"
   with no renew button, and a login is refused. Re-admit it from another device.

## Test 3 — web QR-login with the hardware key (via `LoginApproval`)

The RP backend already exists — run `cmd/void-which-binds login-serve --pin <userId>` (or
a deployed All Thing) and pin the identity from Test 2.
1. The RP shows a `void-which-binds:login?rp=&id=` QR. The app's Scan screen calls
   `VoidbindQr.parse` → `LoginApproval.begin(qr)`; the approval sheet shows the
   audience (RP origin) + a live expiry countdown.
2. Tap Approve → `LoginApproval.approve` calls `DeviceKeyStore.sign`, so the
   **biometric prompt fires** (the SE/StrongBox unseal); the assertion posts.
3. The RP verifies it offline (void-which-binds-go/rp) and mints a short-lived token.
4. Assert: no private key leaves the phone; a **cancelled** biometric prompt yields
   no login; an **unpinned** device is refused (401); an expired challenge is refused.

## Test 4 — add a second device (pairing, `DeviceAuthorization` ↔ `DevicePairing`)

Two devices (or one device + the `void-which-binds pair-*` CLI as the counterpart).
1. On the **existing** device: `DeviceAuthorization.invite(relayBase)` renders the
   pairing QR. The **new** device scans it → `DevicePairing.begin(inviteQr)`; both
   screens run the handshake and show a **7-digit SAS**.
2. Confirm the two numbers match (the human gate). The existing device
   `authorise`s (signs + seals the cert to the new device's X25519 key); the new
   device `confirm`s (unseals + verifies).
3. Assert: the SAS matches only when the two devices are the real pair; a
   mismatched/rushed SAS yields no enrolment; the delivered cert verifies against
   the user key and binds the new device.

## Test 4b — any member adds the next device; Settings → Devices; Remove (ADR-0005)

From 0.5.0 the device that taps "Add a device" does NOT need the recovery secret:
it signs the new device's add op with its own hardware key, citing the heads of the
membership replica in `IdentityStore` (`ops`). A pre-0.5.0 install migrates on first
launch — its v2 cert IS a genesis add, so the replica starts as `[cert]`; nothing is
re-enrolled and nothing is lost.
1. Upgrade in place (`adb install -r`, never uninstall). Open the app: Home still
   shows the same identity fingerprint and this device; Settings → **Devices** lists
   this device, "admitted <date> by genesis (recovery key)".
2. On a PAIRED (non-owner) install, tap **Add a device**: the invite renders without
   any secret; a third device that scans it receives an add signed **by the phone**
   (`Membership.evaluate` on either side finds all three members). The invite is v3
   (`usr=`), and a responder that expects a different identity gets **no SAS**.
3. **Remove** another device from Devices: a **strong-biometric** prompt (no PIN /
   pattern fallback — `PresencePolicy.DESTRUCTIVE`) → a `remove` op signed by this
   device → the row disappears (local evaluation) and the ops are pushed to
   `POST /membership/{usr}` on the heyarr node (:7777) and All Thing (:8080);
   a 404 from an RP that has not landed the route yet is tolerated. The removed
   device is refused at every RP on its next login (its ops travel with the
   assertion, and the RP's log now holds the remove).
   - **Strong-only, device-tested:** the Remove prompt must offer fingerprint/face
     ONLY — confirm there is no "Use PIN/password" option on it (contrast the login-
     approval prompt, which still offers the credential). The same strong-only gate
     guards **Add a device → Authorise** (Test 4b step 2 / Test 4 initiator). On a
     phone with a screen lock but **no biometric enrolled**, both actions must refuse
     with the "needs a fingerprint or face" message and point at recovery — they must
     NOT silently accept the PIN.
4. Login still works: the assertion carries `ops` beside the admitting op (see
   `CoordinatorGoInteropTest`, which proves the Go RP evaluates them).

## Test 5 — same-device handoff: an RP app opens the authenticator by deep link

No second phone. The RP app on the SAME phone launches `void-which-binds:login?rp=&id=` (the
`qr` string its broker returned, optionally `&callback=<app-scheme-uri>`); the
authenticator shows the normal approval sheet and finishes back to the caller (ADR-0003).
Simulate the RP with `adb` against a live node:

```sh
# build + install the REAL engine (the phone must already hold an enrolled identity).
# The app is Cruciform, package one.rarebit.cruciform (ADR-0004); if a pre-0.3.0
# one.rarebit.voidbind install is still present, uninstall it LAST — after the new
# app launches and is enrolled — so only one authenticator claims the voidbind: scheme.
./gradlew -PdeviceEngine=true :androidApp:assembleDebug
adb install -r androidApp/build/outputs/apk/debug/androidApp-debug.apk
# adb uninstall one.rarebit.voidbind   # old package, only once Cruciform is enrolled

# mint a login on the RP (a heyarr dev node on the LAN), then hand it to the authenticator
ID=$(curl -s -X POST http://192.168.16.224:7777/login | sed -E 's/.*"id":"([^"]+)".*/\1/')
adb shell am start -a android.intent.action.VIEW \
  -d "void-which-binds:login?rp=http%3A%2F%2F192.168.16.224%3A7777&id=$ID&callback=heyarr%3A%2F%2Flogin%2Fdone"
```

1. The approval sheet opens (cold start AND with the app already open — `singleTask`
   + `onNewIntent`) showing the **rp origin** `192.168.16.224:7777` and a live expiry;
   nothing was approved by the link itself. A v2 challenge shows the number grid.
2. Tap **Deny**: the activity finishes; the previous app is back in front; no callback
   is launched; `GET /login/$ID` never reports approved.
3. Repeat with a fresh id and tap **Approve** → biometric → the RP's broker poll reports
   approved and (only now) the `callback` is launched bare, if an app handles it.
4. A malformed link (`void-which-binds:login?rp=x`, a `callback=https://…`) opens nothing /
   drops the callback — the URI is untrusted input. Debug builds allow cleartext HTTP so
   the plain-http LAN node works; release builds do not.

## Test 6 — reverse same-device handoff: Cruciform hands its invite to an RP app (ADR-0006)

One phone with Cruciform and an RP app that registers a pair callback (heyarr-mobile
`heyarr-mobile://pair`, All Thing `allthing://pair`). The RP holds its own device key and
needs THIS authenticator to admit it; it cannot scan the screen it shares.

```sh
./gradlew -PdeviceEngine=true :androidApp:assembleDebug
adb install -r androidApp/build/outputs/apk/debug/androidApp-debug.apk     # never uninstall — upgrade in place
```

1. Settings → **Devices** → **Add a device**. The Connect screen shows the invite QR and,
   below it, **"Send to heyarr on this phone"** — one button per registered RP that is
   installed (`RpPairLauncher.resolvable`), plus **"Share invite…"** (Sharesheet). With no
   such app installed, only "Share invite…" shows.
2. Tap **Send to heyarr**: heyarr-mobile foregrounds on its Enrol screen in *Joining…*
   (its `DevicePairing.begin` against the relay named in the invite), then shows its
   **7-digit security code** large. If heyarr has no device key yet it parks the invite,
   asks for the key (fingerprint), then joins.
3. Switch back to Cruciform (recent apps): the invite screen has advanced to **VERIFY**
   with its own 7-digit code — the handshake completed when heyarr joined.
4. Compare the two codes. **Yes, they match** → biometric → the admission is sealed to
   heyarr's device key and delivered; heyarr's screen moves to *Enrolled* and registers
   at the node (`POST /enrol` with `ops`). Settings → Devices on Cruciform now lists the
   phone twice: this device, and "heyarr-mobile on <model>" admitted by this device.
5. Negative: **Share invite…** to any text target shows the raw `void-which-binds:pair?…` tuple
   and nothing else; a login tuple can never be sent through this door (`uriFor`
   refuses it); cancelling on VERIFY leaves heyarr's join to time out with no admission.
