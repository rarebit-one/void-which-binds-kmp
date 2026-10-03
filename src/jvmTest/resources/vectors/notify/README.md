# Notify-channel golden vectors

Vectors for the Void-Which-Binds **notify channels** (ADR-0020, amended
2026-10-03, G10): Web Push (RFC 8030/8291/8292), wake-only Slack DMs, the
per-channel subscription store, and the registration path for passkey-only
people (`Registry.RegisterMember`). void-which-binds-go generates them
(`go test ./notify -run TestNotifyVectors -update`) and replays every file.

The plane is server-side, so most files are Go fixtures. The Web Push
encryption files (`webpush-encrypt`, and the `webpush` part of
`approve-wake`) are the ones void-which-binds-web also runs: its service
worker must decrypt `body` with `ua_private` and `auth` to exactly
`plaintext`. The scenario vectors that need a live store and transports
(`webpush-404/410-deletes-subscription`, `slack-fallback-only`,
`two-channels-one-device`) are Go tests in `notify/channels_test.go`.

Every file has `name` (== the file stem), `description` and `kind`; the rest
depends on the kind. Binary values are unpadded base64url unless noted.

| `kind` | field | what a port checks |
|--------|-------|--------------------|
| `webpush-encrypt` | `webpush` | ECDH(`as_private`, `ua_public`) = `ecdh_secret`; the RFC 8291 §3.3–3.4 key schedule gives `cek` and `nonce`; encrypting `plaintext` with `as_private`, `salt` and record size `rs`, one record with no padding, gives `body`, whose first 86 bytes are `header`; and `body` decrypts back with `ua_private` |
| `vapid` | `vapid` | `authorization` is `vapid t=<jwt>, k=<public>`; the JWT header is exactly `header`; `aud` is `aud` (the endpoint's origin, path stripped); `now` < `exp` ≤ `max_exp` (now + 24 h); `sub` is present; and the ES256 signature (64-byte r‖s) verifies under `k`. Verify-only: ECDSA is randomised |
| `slack-payload` | `slack` | `body` is the exact `chat.postMessage` JSON for `tuple` to the DM `dm` |
| `register-member` | `registry` | `RegisterMember(principal, action, request)` under `config` returns `expect`: `ok`, `unknown_channel`, `endpoint_not_allowed`, `registration_mismatch` or `malformed`; `action.digest` is the ADR-0019 digest of `action` (hex, `""` when it is not well formed); nothing is stored on a refusal |
| `filestore` | `filestore` | the pre-ADR-0020 `file`, loaded, gives `expect` for `users` at `now` (every record on `ntfy`) |
| `approve-wake` | `approve_wake` | `tuple` is `void-which-binds:approve?h=<handle>` and nothing else; the ntfy body is `ntfy_body`; the Slack body to `slack_dm` is `slack_body`; and `webpush` is a `webpush-encrypt` case whose plaintext is the tuple |

`config.channels` lists the configured channel kinds; an empty list is the
zero `Channels` map (the homelab: ntfy only, no endpoint policy). `ntfy_base`,
`webpush_origins` and `slack_directory` configure the three policies, and
`org` is `Registry.Org`.

The registration action (G10d) is `Kind` `notify-register`, `Resource`
`notify:channel/<channel>`, `Summary` the channel's fixed sentence, and
`Params` the canonical JSON of the request:
`{"channel":…,"endpoint":…[,"keys":{"auth":…,"p256dh":…}]}` (keys in byte
order, no whitespace, `keys` only for Web Push). `RegisterMember` compares all
four byte for byte.

All keys are test-only, derived from fixed labels; `rfc8291-section-5-example`
uses RFC 8291 §5's published keys and reproduces its body and Appendix A's
intermediate values exactly.
