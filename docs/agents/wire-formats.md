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
  `void-which-binds.pair-refusal` (`void-which-binds.roster`,
  `void-which-binds.delegation` and `void-which-binds.delegation-pop` are typed by
  their own packages).
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
- **Member keys (ADR-0018).** `MemberKey.parse` accepts `ed25519:<64 lowercase hex>`
  and `webauthn:es256:<130 lowercase hex>` (an on-curve SEC1 uncompressed P-256
  point) and nothing else. `MemberKey.verifyBody(D, B, sig, policy)` picks the scheme
  from the key kind: a raw Ed25519 signature, or the WebAuthn envelope
  `{"ad","cd","sig"}` asserting over `WebAuthn.challenge(D, B)` =
  SHA-256(`void-which-binds/webauthn/challenge/v1` ‖ 0x00 ‖ D ‖ 0x00 ‖ B). Refusal words
  (`MemberKeyFailure.word`) match Go's `MemberKeyReason`; `vectors/webauthn/` (41
  verify-only cases) is replayed by `WebAuthnVectorTest`.
- **Recovery secret** = 256-bit, **bech32m** (BIP-350, *not* bech32) with HRP
  `void-which-binds` (75 characters). A gen1 `heyarr1…` secret is refused with
  `RecoverySecret.GenerationRetiredException` before its checksum is read.
- **URIs.** The scheme is `void-which-binds:` for `login`, `pair` (invite `v=4`),
  `offload-pair` and `unwrap`; a `voidbind:` URI or a `v=3` invite is refused.
- **Headers.** `DeviceCredential.MEMBERSHIP_HEADER` is `Void-Which-Binds-Membership`.
  The org path (void-which-binds-go ADR-0016, G5) adds `Void-Which-Binds-Org` (one
  canonical `ed25519:` org id) and `Void-Which-Binds-Roster` (comma-separated roster
  ops, at most 16, each at most 4 KiB of UTF-8): `RpHeaders` holds the names, caps and
  Go-identical `parse…`/`format…` pairs (refusals `malformed` / `too_many_ops`), and
  `OrgRequest` assembles an org-path request's headers; `vectors/rp-roster/` is
  replayed by `RpRosterHeaderVectorTest` (headers only; the RP evaluation is Go's).
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
- **Roster cosign transport (void-which-binds-go ADR-0014 "Proposal transport", G4).**
  Two relay slots (`RelayClient.COSIGN_TYPES` = `proposal`, `cosig`; slot bound
  `COSIGN_MAX_MESSAGE_BYTES` = 512 KiB) carry
  `{"v":1,"slot":"proposal","core","usr"?,"bprev"?,"roster":[…],"persons":{…}}` and
  `{"v":1,"slot":"cosig","entry":{"by","usr","bprev"?,"sig"},"persons":{…}}`. A payload
  must be exactly Go's `json.Marshal` of what it parses to; caps (512/128 KiB, 256 roster
  ops, 64 persons, 256 / 128 person ops) are checked before any token is parsed. Which
  refusal a non-canonical payload gets depends on how Go's struct decoding reads it
  (case-folded keys, last duplicate wins, `null` leaves a scalar), so
  `roster/proposal` decodes through `GoJson`, not `MiniJson`. Refusal reasons and their
  order are Go's; `vectors/roster-proposal/` (19 cases) is replayed by
  `RosterProposalVectorTest`, which re-mints every `ok` cosig and assembled op byte for byte.
- **Delegation grant (void-which-binds-go ADR-0017, G8), minting side.**
  `delegation.Delegation` mints `void-which-binds.delegation` v1: body
  `{"v":1,"typ","usr","org","iss","prn","aud","scp":[…],"jti","non","iat","exp"}`, exactly
  Go's `json.Marshal` (compact, HTML-escaped: `&` in an `aud` is `\u0026`, rendered
  through `GoJson.appendString`). `scp` is canonicalised at mint (`scope.Scope`: sorted,
  de-duplicated, 1–32 scopes of `<ns>:<path>`); `jti` (16 bytes) and the broker's `non`
  (32 bytes) are strict unpadded base64url; `exp − iat` ≤ 24 h. An Ed25519 member key
  mints with `signWith`; a `webauthn:` passkey asserts over
  `challenge(body)` = `WebAuthn.challenge("void-which-binds.delegation", body)` and
  `assembleWebAuthn(body, webAuthnEnvelope(ad, cd, sig))` joins the token. The agent
  proves possession with `signProofWith`: `void-which-binds.delegation-pop`
  `{"v":1,"typ","dlg","aud","iat","exp"}`, `dlg` = base64url(sha256(delegation BODY)),
  ttl ≤ 120 s. `parse` refuses anything but the canonical encoding (`malformed`) or
  another `typ` (`wrong_type`). The broker's `Verify` is server-only and not ported.
  `vectors/delegation/` (52 cases) is replayed by `DelegationVectorTest`, which re-mints
  every Ed25519 delegation and proof byte for byte and reproduces every passkey body
  and challenge; `vectors/scope/` by `ScopeVectorTest`.
- **Action approval (void-which-binds-go ADR-0019, G9a), approver side.** `approval.Approval`
  parses the wake `void-which-binds:approve?h=<43 b64url>` as an exact string (no trim,
  no URI parse); handles and nonces are 32 non-zero bytes of canonical unpadded base64url
  (re-encode compare, so CR/LF, padding and stray trailing bits are refused). Frames are
  `uint64be(len) ‖ bytes`. Action digest = SHA-256(frame(`void-which-binds/approval/action/v1`)
  ‖ kind ‖ resource ‖ summary ‖ params); challenge preimage = frame(`…/approval/challenge/v1`)
  ‖ id ‖ nonce ‖ audience ‖ u64(exp) ‖ u64(match) ‖ digest ‖ resource ‖ u64(ttl); fetch
  preimage = frame(`…/approval/fetch/v1`) ‖ audience ‖ handle ‖ nonce. A passkey asserts over
  `WebAuthn.challenge(domain, preimage)`. `net.ApprovalClient` POSTs `/approval/fetch-nonce`
  and `/approval/fetch` (`{handle,nonce,credential,ops,roster,proof}`, the ops from an
  `OrgRequest`; no org header — the broker uses its own org). The answer is decoded as Go's
  `json.Unmarshal` does (`GoJson`, folded keys, merged duplicates, Go's UTF-8 replacement)
  and `FetchResponse.open` recomputes the digest over the fetched bytes (never
  canonicalised). Every refusal is `404 {"error":"not_found"}`. The approval body is
  `{"credential","ops"?,"roster"?,"sig","match_number"}`; the chosen number must be one of
  the candidates. `vectors/approval/` (28 cases) is replayed by `ApprovalVectorTest`.
