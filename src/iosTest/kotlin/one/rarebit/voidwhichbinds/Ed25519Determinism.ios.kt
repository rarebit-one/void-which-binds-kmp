package one.rarebit.voidwhichbinds

// CryptoKit signs Ed25519 with randomized (hedged) nonces, so signature bytes are
// not reproducible. They still verify.
internal actual val ed25519SigningIsDeterministic: Boolean = false
