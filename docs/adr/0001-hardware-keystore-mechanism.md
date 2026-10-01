# 0001. Hardware keystore mechanism: seal a software Ed25519 key with a non-extractable hardware wrapping key

<!-- k0:keep name-note -->
> **Name note (void-which-binds-go ADR-0013).** The protocol is now Void-Which-Binds
> and this repo is `void-which-binds-kmp` (package `one.rarebit.voidwhichbinds`).
> This record is kept as written, in gen1 names.

**Status:** Accepted
**Date:** 2026-08-27
**Refines:** voidbind-go `docs/adr/0001-device-key-model.md` (the primitive decision)

## Context

voidbind-go ADR-0001 settled the *primitive* question: **keep Ed25519 (signing)
and X25519 (key-agreement)** as the wire + signing primitives, achieve
device-binding through **hardware-gated storage** rather than enclave-native
signing, and **defer** true enclave-native P-256 signing behind the cert
`Version` enum. That decision stands, unchanged, and this record does not reopen
it.

What voidbind-go ADR-0001 left as a leaning rather than a mechanism is *how*
`voidbind-kmp` makes the Ed25519 device key non-extractable on each platform. It
described two different-looking paths:

- **iOS:** a software Ed25519 key **sealed at rest by a Secure-Enclave P-256 key**
  + biometric — because the Secure Enclave holds **P-256 only**, never Ed25519.
- **Android:** the Ed25519 signing key **generated non-extractable in
  StrongBox / Keystore where the platform supports it.**

Implementing the `actual DeviceKeyStore` forces the concrete question, and
surfaces a fact that makes those two paths converge:

> **AndroidKeyStore cannot hold an Ed25519 signing key either.** The
> AndroidKeyStore provider supports RSA, EC over the NIST prime curves
> (P-256/384/521), and AES/HMAC. It has **no** `KEY_ALGORITHM_ED25519`, and no
> StrongBox/TEE surface that generates or signs with a native, non-extractable
> Ed25519 key on shipping devices. So the "non-extractable Ed25519 in StrongBox"
> path is, in practice, **unavailable** — exactly the same wall the Secure
> Enclave hits.

So both secure elements can hold a **non-extractable NIST-EC or AES key**, and
neither can hold an Ed25519 key. Ed25519 must therefore be a **software key on
both platforms**, and the hardware's job on both platforms is the same: hold a
non-extractable **wrapping key** that seals the Ed25519 private scalar at rest
and gates every use behind the secure element + user presence.

## Decision

**On every hardware target, the Ed25519 device signing key is a software key
whose private scalar is sealed at rest by a non-extractable wrapping key held in
the platform secure element, unsealed only transiently — behind hardware +
biometric/passcode — for the duration of a single signing operation, then
zeroized.** The mechanism is symmetric across platforms:

| | Wrapping key (hardware, non-extractable) | Seal / unseal | User-presence gate |
|---|---|---|---|
| **Android** | AES-256-GCM in AndroidKeyStore, `setIsStrongBoxBacked(true)` where the device has a StrongBox secure element (TEE-backed otherwise) | AES-GCM encrypt/decrypt of the Ed25519 seed | `setUserAuthenticationRequired(true)` (BiometricPrompt / device credential) |
| **iOS** | P-256 in the Secure Enclave (`kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent`) | ECIES to/from the SE public key (`SecKeyCreateEncryptedData` / `…DecryptedData`, `eciesEncryptionCofactorX963SHA256AESGCM`) | `SecAccessControl` `.privateKeyUsage` + `.biometryCurrentSet` / `.userPresence` |
| **JVM** | none — software key in-heap | none | none — `isHardwareBacked = false`, dev/test only |

- **The Ed25519 private scalar exists in plaintext only transiently**, in
  process memory, immediately after a hardware- and biometric-gated unseal, and
  is zeroized after the signature is produced. At rest it is only ever the
  sealed blob; the wrapping key never leaves the secure element.
- **Where a platform *does* expose a native, non-extractable Ed25519 signing
  key**, the `actual` for that platform may use it directly and skip the seal —
  the store's contract (`publicKey()` / `sign()` / `isHardwareBacked`) is
  identical either way. None of today's shipping platforms do.

This **updates** voidbind-go ADR-0001's Android bullet: Android uses the *same
sealing model as iOS*, not a native non-extractable Ed25519 key, because
AndroidKeyStore has no such key.

## Consequences

- **Non-extractability holds at rest and every use is hardware-gated.** An
  attacker with the device's flash but not the secure element cannot recover the
  key; no signature can be produced without the secure element **and** a fresh
  user-presence check. This is the property voidbind exists to add over heyarr's
  plaintext-seed-file CLI store.
- **Threat model, stated plainly (not implied away).** Because Ed25519 is a
  software key while resident, the scalar is **extractable-in-principle to an
  attacker who already has code execution inside the app process at the moment
  of a signature** — on both platforms. The hardware guarantees non-extractability
  **at rest** and gates every use; it does not defend a fully-compromised live
  process. A native non-extractable *signing* key (the deferred P-256 path) is
  strictly stronger and is what the `Version`-enum seam is held open for. This is
  a large improvement over a plaintext seed file and is honest about its ceiling.
- **The store is not a port of heyarr's `internal/device`** (seed files on disk),
  as voidbind-go ADR-0001 already noted — it is a fresh `expect`/`actual` over
  StrongBox-sealed vs Secure-Enclave-sealed storage.
- **Recovery is unchanged** (heyarr ADR-0022): the recovery secret rebuilds the
  identity offline; the enclave holds device keys, never the recovery root. A
  lost phone re-enrols by pairing or by recovery.
- **Enclave-native P-256 signing stays deferred** behind the cert `Version` enum
  (voidbind-go ADR-0001). When threaded through
  `identity`/`enrolment`/`grant`/`deviceauth`/mTLS, both platforms hold a native
  P-256 signing key and the software-seal falls away.

## Software crypto engine (Ed25519 + AES-GCM/ECIES) — how, without hand-rolling

The seal/unseal wrapping key is **platform-native** (AndroidKeyStore JCA /
Security.framework) — never a library. But the **software** operations —
Ed25519 keygen + signing, and the AES-GCM used inside the Android seal — need a
constant-time implementation on **Kotlin/Native (iOS)** too, where there is no
`java.security`. Ed25519 is **not** hand-rolled (timing-attack surface); it is
supplied by a vetted multiplatform provider that delegates to OS/vetted
primitives:

- **JVM / Android:** the JDK / Conscrypt provider (Ed25519 is standard from JDK
  15; Android via the bundled provider), as `JvmEd25519` already does.
- **Kotlin/Native (iOS):** a vetted multiplatform crypto provider
  (recommended: `dev.whyoleg.cryptography:cryptography-kotlin`, OpenSSL3-backed
  on Apple targets) for Ed25519 signing; the Secure Enclave supplies only the
  wrapping key via Security.framework.

Adopting a multiplatform crypto provider is a dependency decision for the
identity library and is called out for explicit confirmation before the iOS
`actual` is built on it; it delegates to vetted primitives (OpenSSL / the JDK),
it is not a "central authority", and it never touches the hardware wrapping key.

## What would make us revisit

- A shipping secure element that generates and signs with a **native
  non-extractable Ed25519** key → the `actual` uses it directly, seal removed.
- The **algorithm-agility milestone** (voidbind-go ADR-0001): native P-256
  signing behind the `Version` enum supersedes the software-Ed25519 seal.
