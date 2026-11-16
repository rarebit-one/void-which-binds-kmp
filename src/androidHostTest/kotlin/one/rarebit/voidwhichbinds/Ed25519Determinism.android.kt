package one.rarebit.voidwhichbinds

// The JDK Ed25519 provider signs deterministically (RFC 8032).
internal actual val ed25519SigningIsDeterministic: Boolean = true
