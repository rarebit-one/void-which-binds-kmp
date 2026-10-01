# 0007. A minted pairing invite is owned by the app, not by the screen that shows it

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-09-03
**Relates to:** ADR-0005 (any member mints the invite), ADR-0006 (the same-phone handoff to a
relying-party app), voidbind-go `relay.DefaultSessionTTL`.

## Context

The initiator side of pairing — Settings → Devices → *Add a device* — minted an invite and
then ran the relay handshake (`awaitPairHandshake`: post commit, poll for the responder's
commit, post reveal, poll for the reveal, derive the SAS) inside a `LaunchedEffect(invite)`
on the Connect screen. ADR-0006 then added the same-phone handoff: the invite is sent to
heyarr-mobile / All Thing on the SAME phone by deep link.

That combination is broken by construction. The relying-party app has to create its device
key (a fingerprint, tens of seconds) before it joins the relay. The moment the user switches
to it, Cruciform's Connect screen leaves composition, the `LaunchedEffect` is cancelled, and
the initiator never posts its reveal. The heyarr node's relay log showed the shape exactly:
for session `f392013f` the responder posted `commit` + `reveal`, the initiator never PUT its
reveal; and Cruciform minted **6 invites in 12 minutes** — every return to the screen either
re-ran the effect (a spent session → "can't reach the relay"/timeout) or re-minted.

Two smaller faults compounded it: the library's `RelayClient` poll bound was 60 s (a
transport-sized number) while the relay session lives 10 min, so even an initiator that was
never cancelled gave up before a human-paced responder arrived; and the Connect screen's
countdown was a `remember` that restarted from 300 s on every re-entry, so the timer lied.

## Decision

1. **The invite lifecycle is an app-scoped state machine, `InviteCoordinator`**, owned by
   `AppViewModel` (`viewModelScope`) and keyed by the minted invite. Its states are
   `Idle → Minting → Waiting → Joined → Confirming → Admitted`, with `Failed(phase)`.
   Screens **observe** `state`; nothing in the UI starts, restarts, or cancels the handshake
   on recomposition or on return. Explicit human actions do: Back on Connect / Cancel on
   Verify → `cancel()`; the SAS match → `confirm()`.
2. **`ensureInvite()` never re-mints while an invite is live** (minting, waiting, joined,
   confirming). *Add a device* pressed twice, a return from the RP app, and the
   "Send to <app> on this phone" tap all leave the relay session alone.
3. **The wait is bounded by the relay session TTL, with a visible countdown.**
   `DeviceAuthorization` / `RelayClient` take a `maxWaitMillis`; the engine passes
   `INVITE_TTL_SECONDS` (600 — voidbind-go `relay.DefaultSessionTTL`, the heyarr node's
   value). The countdown on the Connect screen is `coordinator.remainingSeconds()` — one
   deadline, the same clock however the screen is entered.
4. **A foreground service holds the process while waiting.** `PairInviteService`
   (`foregroundServiceType="dataSync"`, notification "Waiting for the new device to join…")
   is started at `Waiting` and stopped at `Joined`/`Failed`/`cancel()` through the
   `ProcessKeepAlive` seam. It does no work itself; the coordinator's job does. If Android
   refuses to start it, the wait still runs in the ViewModel scope — it is a guarantee, not
   a dependency.
5. **On return to Cruciform, `Joined` is already the state → VERIFY with the SAS.** The nav
   graph reacts to the coordinator's state wherever the user is; the Connect screen is not
   involved in the transition.
6. **Failures are classified against what the session already proved.** Once an invite is
   minted the relay has answered, so a transport failure during the wait is reported as the
   relay *dropping* (not "can't reach the relay" → check Wi-Fi), a `TIMEOUT` well before the
   deadline as the transport giving up early, and only a `TIMEOUT` at the deadline as the
   invite expiring. An interrupted blocking call is `CANCELLED`, not `UNREACHABLE`. Retry
   re-runs the right step: a fresh invite after a spent session, a re-confirm of the SAME
   session after a delivery failure.

## Consequences

- The invite outlives the screen and the app being backgrounded, up to 10 minutes. An
  abandoned invite still costs one relay session, which expires on its own.
- Three new permissions: `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC` (install-time)
  and `POST_NOTIFICATIONS` (runtime; not requested yet — the service runs without it, the
  notification is simply not shown).
- The state machine is pure Kotlin and unit-tested on the JVM with a fake engine
  (`InviteCoordinatorTest`): one mint per Add, no re-mint while live, the wait outlives the
  observer, keep-alive held exactly for the wait, each phase's Retry, cancel drops a late join.
- The responder (join) path is unchanged; it already runs to completion in a coroutine that
  is not tied to a screen.
