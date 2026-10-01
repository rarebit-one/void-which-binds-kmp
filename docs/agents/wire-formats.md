# Wire formats

Moved verbatim from the old `CLAUDE.md` ("Wire formats"). The rule that governs all of it is in [`AGENTS.md`](../../AGENTS.md): mirror void-which-binds-go exactly.

- **Enrolment cert token** = `base64url(json payload) + "." + base64url(ed25519 sig)`.
  `base64url` is URL-safe, **no padding** (Go's `RawURLEncoding`). The payload is
  **compact** JSON with fields in this exact order (they are signed as-is):
  `{v, typ, usr, dev, denc, iat, exp}`. The signer is the **user identity** key.
- **Membership op token** (v3, ADR-0005) = the same `base64url(payload).base64url(sig)`
  shape with payload `{v:3, typ, usr, op, dev, denc?, by, prev:[…], cosig?, iat, exp?}` in
  that order, signed by `by` (a member device key, or `usr` for genesis). A v1/v2 cert
  IS a v3 add signed by genesis with no `prev`. `Membership.evaluate` is a line-for-line
  port of void-which-binds-go `enrolment.Evaluate`; the golden vectors in
  `src/jvmTest/resources/vectors/membership/` (27 today, incl. the ADR-0008 cosig
  cases, the ADR-0022 gen1 refusals and the ADR-0018 `webauthn-*` high-water cases) are copied from void-which-binds-go's `testvectors/vectors/` and must replay
  byte-for-byte — never edit them here, re-copy from Go and bump
  `src/jvmTest/resources/vectors/VOID_WHICH_BINDS_GO_REF`; the `vector-drift` CI job
  (`scripts/check-vector-drift.sh`) fails on any difference. `MembershipVectorTest` enumerates the directory, so a
  newly copied vector is picked up automatically.
- **Token type (`typ`, void-which-binds-go ADR-0009).** Every signed token carries a
  `typ` member, placed second in the body right after `v`: `void-which-binds.cert`,
  `void-which-binds.possession`, `void-which-binds.op`, `void-which-binds.grant` or
  `void-which-binds.pair-refusal` (`void-which-binds.roster` and
  `void-which-binds.delegation` are reserved).
  - **Gen2 is typed-only (ADR-0022).** Every minter emits `typ`
    (`MembershipOp.sign`, `PossessionProof.mint`/`signingBytes`, `Cert`), and
    [`TokenType.check`](../../src/commonMain/kotlin/one/rarebit/voidwhichbinds/TokenType.kt)
    refuses an absent `typ` exactly like a foreign one (`WRONG_TYPE`), straight
    after the token is split and before the signature. A gen1 token (untyped, or a
    `voidbind.*` value) is simply foreign: there is no generation dispatch.
  - `MembershipOp.coreBytes` includes `typ`, which the cosig preimage needs; the
    cosig domain is `void-which-binds-cosig-v1\0`, and `MembershipOp.verifyCosig`
    checks one cosig (a gen1-domain cosig never verifies, so never counts).
  - `vectors/typ/` holds one verdict per check, replayed by `TypVectorTest`.
- **High-water N (ADR-0008, ADR-0018).** Rule 5's N counts only members that can
  cosign: Ed25519 keys (`canCosign`). A `webauthn:` passkey member is still a member
  but never raises N.
- **Recovery secret** = 256-bit, **bech32m** (BIP-350, *not* bech32) with HRP
  `void-which-binds` (75 characters). A gen1 `heyarr1…` secret is refused with
  `RecoverySecret.GenerationRetiredException` before its checksum is read.
- **URIs.** The scheme is `void-which-binds:` for `login`, `pair` (invite `v=4`),
  `offload-pair` and `unwrap`; a `voidbind:` URI or a `v=3` invite is refused.
- **Headers.** `DeviceCredential.MEMBERSHIP_HEADER` is `Void-Which-Binds-Membership`.
- **Pairing** = short-authentication-string with **commit-before-reveal**: each
  side commits to its nonce (H(label ‖ role ‖ nonce)) before either nonce is
  revealed, so neither party can bias the final digits; both derive the SAS from a
  bound transcript and humans compare it out-of-band. Under ADR-0005 the initiator
  is ANY member device (`PairflowAuthority.Device`, or `Genesis` for the first
  device / recovery): the invite is v4 (`usr`; v3's fields under the gen2 scheme), the initiator's reveal carries its
  `ops`, the responder EVALUATES them and refuses a non-member before any SAS
  exists, and the sealed `cert` message carries the admission `{op, ops}`.
  Instead of authorising, the initiator may post a signed **refusal**
  (`PairRefusal`, void-which-binds-go ADR-0012) to its `refuse` slot. The token is
  `{v:1, typ:"void-which-binds.pair-refusal", by, ses}`, where `ses` binds the session salt
  under `void-which-binds/pairflow/refusal/session/v1`.
  `PairflowResponder.receive` watches that slot (`RelayClient.fetchWatching`) and
  throws `PairingRefusedException` for a refusal that verifies, instead of timing
  out. It ignores anything else there.
