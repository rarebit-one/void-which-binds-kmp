# Source layout

Moved verbatim from the old `CLAUDE.md` ("Layout"): an annotated source map.

```
src/
  commonMain/kotlin/one/rarebit/voidwhichbinds/
    Labels.kt          identity-defining constants (DO NOT rename)
    KeyRef.kt          ed25519:/x25519: hex rendering + parse
    MemberKey.kt       ADR-0018 member keys (ed25519: / webauthn:es256:): parse, verifyBody, refusal words
    WebAuthn.kt        ADR-0018 challenge derivation + WebAuthn assertion checks (§7.2 order), policy
    RecoverySecret.kt  256-bit bech32m secret (HRP void-which-binds; gen1 heyarr1… refused)
    RecoveryShares.kt  the Void-Which-Binds SLIP-39 profile: split/combine a RecoverySecret as
                       2-of-3 shares (void-which-binds-go ADR-0011, recovery.SplitShares/CombineShares)
    slip39/            SLIP-39 port of void-which-binds-go recovery/slip39: wordlist (SHA-256 pinned),
                       RS1024, GF(256) Shamir, PBKDF2 Feistel, typed Slip39Exception;
                       Trezor's 45 vectors in jvmTest resources vectors/slip39/
    Cert.kt            enrolment cert model + token encode/parse/verify
    MembershipOp.kt    v3 membership op (add/remove) sign/verify/hash; v1/v2 certs read as genesis adds
    Membership.kt      the CRDT evaluator (void-which-binds-go enrolment.Evaluate, ADR-0007) + merge,
                       memberAt (enrolment.MemberAt, the roster's person-signature check)
    OpDag.kt           content-addressed op DAG (void-which-binds-go internal/opdag), iterative walks;
                       shared by Membership and the roster
    roster/            org roster (void-which-binds-go roster, ADR-0014/0015): op wire (Roster,
                       RosterDraft/RosterOp), the evaluator (RosterEvaluator, RosterView);
                       vectors/roster/ replayed by RosterVectorTest; parseCore, verifyDraftCosig,
                       checkDraftClosure, authorityOnly (Go roster/core.go)
    roster/proposal/   the roster cosign transport (void-which-binds-go roster/proposal, ADR-0014
                       "Proposal transport"): proposal/cosig slot payloads (canonical JSON, caps),
                       RosterProposal.check, Checked.cosign/verifyCosig/assemble, context;
                       vectors/roster-proposal/ replayed by RosterProposalVectorTest
    delegation/        the delegation grant, minting side (void-which-binds-go delegation,
                       ADR-0017): Delegation.body/signWith, passkey challenge +
                       assembleWebAuthn, agent signProofWith, parse; vectors/delegation/
                       replayed by DelegationVectorTest
    scope/             scope grammar + canonical scope lists (void-which-binds-go scope);
                       vectors/scope/ replayed by ScopeVectorTest
    Ed25519.kt         signer/verifier seams; Ed25519Engine.kt = software Ed25519 (cryptography-kotlin)
    Pairing.kt         commit-before-reveal SAS derivation
    UserIdentity.kt / DeviceIdentity.kt / Enrolment.kt   identity + self-enrolment
    Invite.kt / LoginQr.kt / WebLogin.kt / DeepLink.kt / PushPing.kt   QR, deep-link, push wire
    DeviceKeyStore.kt  expect: hardware signing key
    auth/              Device-scheme possession proof, credential, 401 re-mint policy;
                       RpHeaders (org/roster/membership header names, caps, Go-identical
                       parse/format) and OrgRequest (the org-path request's headers, ADR-0016)
    net/               HttpTransport seam; Relay/Pairflow/WebLogin/Notify clients; cert sealer
    flow/              LoginApproval / DevicePairing / DeviceAuthorization coordinators
    offload/           cruciform-offload wire + phone responders (ADR-0098)
    policy/            per-RP approval policy (ADR-0002)
    crypto/            Hex, Base64Url (no-pad), Bech32m, MiniJson (compact, ordered),
                       X25519, Ed25519Group, XChaCha20-Poly1305, VoidbindEncryption, expect AEAD,
                       P256 (point validation), Es256 (provider ECDSA verify), StrictJson,
                       GoJson (iterative reader + string encoder with Go encoding/json semantics),
                       GoStrings (Go TrimSpace whitespace, UTF-8 len)
  commonTest/…         pure + cryptography-kotlin tests (run on every target)
  jvmMain/…            DeviceKeyStore actual (software), JdkHttpTransport, AEAD actual
  jvmTest/…            JvmEd25519 (JDK provider, test-only) + keystore test; golden-vector
                       parity (resources/vectors/ = void-which-binds-go testdata, verbatim);
                       live void-which-binds-go interop
  androidMain/…        DeviceKeyStore actual (StrongBox/TEE AES-GCM seal), VoidbindAndroid
  iosMain/…            DeviceKeyStore actual (Secure-Enclave seal via SecureEnclaveSealer), VoidbindIos
androidApp/            Cruciform Android app (Compose), depends on project(":")
iosApp/                Cruciform iOS app (SwiftUI, XcodeGen), links VoidWhichBinds.xcframework
```
