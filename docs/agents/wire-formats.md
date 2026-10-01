# Wire formats

Moved verbatim from the old `CLAUDE.md` ("Wire formats"). The rule that governs all of it is in [`AGENTS.md`](../../AGENTS.md): mirror void-which-binds-go exactly.

- **Enrolment cert token** = `base64url(json payload) + "." + base64url(ed25519 sig)`.
  `base64url` is URL-safe, **no padding** (Go's `RawURLEncoding`). The payload is
  **compact** JSON with fields in this exact order (they are signed as-is):
  `{v, usr, dev, denc, iat, exp}`. The signer is the **user identity** key.
- **Membership op token** (v3, ADR-0005) = the same `base64url(payload).base64url(sig)`
  shape with payload `{v:3, usr, op, dev, denc?, by, prev:[…], cosig?, iat, exp?}` in
  that order, signed by `by` (a member device key, or `usr` for genesis). A v1/v2 cert
  IS a v3 add signed by genesis with no `prev`. `Membership.evaluate` is a line-for-line
  port of void-which-binds-go `enrolment.Evaluate`; the golden vectors in
  `src/jvmTest/resources/vectors/membership/` (25 today, incl. the ADR-0008 cosig
  cases) are copied from void-which-binds-go's `testvectors/vectors/` and must replay
  byte-for-byte — never edit them here, re-copy from Go and bump
  `src/jvmTest/resources/vectors/VOID_WHICH_BINDS_GO_REF`; the `vector-drift` CI job
  (`scripts/check-vector-drift.sh`) fails on any difference. `MembershipVectorTest` enumerates the directory, so a
  newly copied vector is picked up automatically.
- **Token type (`typ`, void-which-binds-go ADR-0009).** Every signed token carries a
  `typ` member, placed second in the body right after `v`: `voidbind.cert`,
  `voidbind.possession`, `voidbind.op` or `voidbind.grant`.
  - **Phase 2 ("emit") is implemented.** The minters emit `typ`:
    `MembershipOp.sign`, `PossessionProof.mint`/`signingBytes`, and a new `Cert`
    (`typ` defaults to `voidbind.cert`).
  - Verification is phase 1's:
    [`TokenType.check`](../../src/commonMain/kotlin/one/rarebit/voidwhichbinds/TokenType.kt)
    checks a present `typ` straight after the token is split, and an untyped
    token still takes the legacy path.
  - `MembershipOp.coreBytes` includes `typ`, which the cosig preimage needs.
  - The untyped mint paths (`signTyped("")`, `mintTyped("")`, `Cert(typ = "")`)
    exist only to reproduce legacy Go goldens in tests.
  - `vectors/typ/` holds the phase verdicts, replayed by `TypVectorTest`.
    `device-scheme-vector-typed.json` is the credential the public minters must
    produce.
- **Recovery secret** = 256-bit, **bech32m** (BIP-350, *not* bech32) with HRP
  `heyarr`.
- **Pairing** = short-authentication-string with **commit-before-reveal**: each
  side commits to its nonce (H(label ‖ role ‖ nonce)) before either nonce is
  revealed, so neither party can bias the final digits; both derive the SAS from a
  bound transcript and humans compare it out-of-band. Under ADR-0005 the initiator
  is ANY member device (`PairflowAuthority.Device`, or `Genesis` for the first
  device / recovery): the invite is v3 (`usr`), the initiator's reveal carries its
  `ops`, the responder EVALUATES them and refuses a non-member before any SAS
  exists, and the sealed `cert` message carries the admission `{op, ops}`.
  Instead of authorising, the initiator may post a signed **refusal**
  (`PairRefusal`, void-which-binds-go ADR-0012) to its `refuse` slot. The token is
  `{v:1, typ:"voidbind.pair-refusal", by, ses}`, where `ses` binds the session salt.
  `PairflowResponder.receive` watches that slot (`RelayClient.fetchWatching`) and
  throws `PairingRefusedException` for a refusal that verifies, instead of timing
  out. It ignores anything else there.
