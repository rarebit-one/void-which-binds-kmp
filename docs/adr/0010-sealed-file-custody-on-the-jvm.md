# 0010. Sealed-file device custody on the JVM (desktop), byte-compatible with Go

**Status:** Accepted
**Date:** 2026-10-18
**Relates to:** void-which-binds-go ADR-0021 (the custody seam; backend 2, the passphrase-sealed
file), ADR-0001 (hardware keystores on phones). Part of #127 (a desktop Cruciform).

## Context

A desktop has no Secure Enclave or StrongBox. void-which-binds-go keeps a desktop's gen2 device
keys in a **passphrase-sealed file** (`custody/sealedfile`: Argon2id, then XChaCha20-Poly1305 over
the seeds, with the clear header as additional data), and its CLIs and heyarr open it. A JVM
process that holds the same device (a desktop Cruciform, a JVM sync daemon) needs to read and
write that file itself, byte for byte, rather than keep a plaintext seed or shell out to a Go CLI.

This library's JVM target was dev/test only: `DeviceKeyStore`'s JVM actual is a software key that
must never ship as production signing. Sealed-file custody is a different thing: it is the Go
backend's own security model (a stolen disk is safe; code running as the user is not), stated
plainly, not a hardware claim.

## Decision

1. **`custody/SealedFile` in `jvmMain`** reads and writes the Go blob exactly: the same magic,
   layout, KDF floor and ceiling, layout rules and one error per Go error path. `parse` refuses
   everything it can from the clear header before any derivation; `open` checks the plaintext
   repeats the header and that each seed backs its clear key, and fails opaquely otherwise.
2. **Pinned by void-which-binds-go's `custody-sealedfile` vector**, already copied under
   `vectors/` at the current `VOID_WHICH_BINDS_GO_REF`: Kotlin opens Go's blob, re-seals the same
   inputs to the same bytes, and refuses all 14 refusal rows with Go's error kinds, the
   before-derivation rows from `parse` alone.
3. **Argon2id from BouncyCastle (`bcprov-jdk18on`), in `jvmMain` only.** Neither
   cryptography-kotlin 0.6.0 nor the JDK has Argon2id, and a hand-written Argon2 is a larger
   audit surface than a vetted implementation. `commonMain` keeps cryptography-kotlin as its one
   dependency; Android and iOS do not pull BouncyCastle.
4. **XChaCha20-Poly1305 is the existing `crypto/XChaCha20Poly1305`** (a hand-written HChaCha20
   subkey step over the platform IETF ChaCha20-Poly1305 actuals), now zeroing its subkey after use.
   HChaCha20 is also pinned by draft-irtf-cfrg-xchacha's test vector, cross-checked against Go's
   `chacha20.HChaCha20`.

## Consequences

- A JVM process can hold a sealed-file device with no plaintext seed and no Go dependency; the
  desktop Cruciform (#127) and a JVM sync daemon can share it.
- The published JVM artifact gains a BouncyCastle dependency (~8 MB). Phones are unaffected.
- What it protects is exactly the Go backend's: a stolen disk or a copy of the file is useless
  without the passphrase (offline guessing is slowed only by Argon2id); code running as the user
  can capture the passphrase or read open seeds. `Opened.close()` zeroes what it holds, best effort.
  No doc may call it hardware-backed.
