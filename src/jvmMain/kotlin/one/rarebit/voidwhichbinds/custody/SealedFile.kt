@file:Suppress("MagicNumber", "ReturnCount", "ThrowsCount")
// A byte-level codec ported from Go: offsets, shifts and one refusal per Go error path, kept
// one-for-one with custody/sealedfile so a reviewer can diff them (as GoJson.kt does).

package one.rarebit.voidwhichbinds.custody

import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.X25519
import one.rarebit.voidwhichbinds.crypto.XChaCha20Poly1305
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.GeneralSecurityException
import java.security.SecureRandom

/**
 * The passphrase-sealed device key file of void-which-binds-go's `custody/sealedfile`
 * (its ADR-0021, backend 2), read and written on the JVM, byte for byte: a desktop holds its
 * device keys here instead of in seed files (ADR-0010). Pinned by void-which-binds-go's
 * `custody-sealedfile` golden vector, which this library replays.
 *
 * The blob (all integers big-endian):
 *
 *     magic 32 "void-which-binds-sealed-file-v1\0" | kdf id 1 (0x01 Argon2id)
 *     | time 4 | memory KiB 4 | parallelism 1 | salt 32 | nonce 24 | count 1
 *     | count × (kind 1 | name length 1 | name | public key 32)
 *     | XChaCha20-Poly1305( count × (kind 1 | name length 1 | name | seed 32) )
 *
 * Everything before the ciphertext is the AEAD's additional data. The clear public keys
 * answer [recipientId] and [signerId] without the passphrase. [parse] refuses everything it
 * can from the clear header alone (magic, KDF id, the parameter floor and ceiling, the object
 * layout, the exact ciphertext length), before any key derivation.
 *
 * What it protects, stated plainly (as the Go package does): a stolen disk or a copy of the
 * file cannot be opened without the passphrase, and an attacker who has the file can guess
 * offline, slowed only by the Argon2id cost. It does NOT protect against code running as the
 * user: it can capture the passphrase or read the seeds from memory while they are open. It is
 * not hardware-backed, and no doc may say it is. [Opened.close] zeroes what it holds, as best
 * effort only.
 */
class SealedFile private constructor(
    /** The KDF parameters this file was sealed under. */
    val params: Params,
    /** The clear objects, in file order: the X25519 one (if any) first, then named Ed25519 ones. */
    val objects: List<Entry>,
    private val salt: ByteArray,
    private val nonce: ByteArray,
    private val ad: ByteArray,
    private val ciphertext: ByteArray,
) {
    /** A key kind; the same bytes as the Go blob. */
    enum class Kind(val byte: Byte) {
        X25519(0x01),
        ED25519(0x02),
    }

    /** One clear header object: its kind, its name ("" for the X25519 one) and public key. */
    class Entry(val kind: Kind, val name: String, publicKey: ByteArray) {
        private val pub = publicKey.copyOf()
        val publicKey: ByteArray get() = pub.copyOf()

        /** `x25519:<hex>` or `ed25519:<hex>`. */
        fun rendered(): String = when (kind) {
            Kind.X25519 -> KeyRef.x25519(pub).render()
            Kind.ED25519 -> KeyRef.ed25519(pub).render()
        }
    }

    /** One seed to seal. The seed is not kept or modified; the caller zeroes its copy. */
    class Object(val kind: Kind, val name: String, val seed: ByteArray)

    /** Argon2id cost parameters, bounded by [FLOOR] and [CEILING] component-wise. */
    data class Params(val time: Long, val memoryKiB: Long, val parallelism: Int) {
        companion object {
            /** The floor (ADR-0021): time 3, 256 MiB, 1 lane. Also the default. */
            val FLOOR = Params(3, 262_144, 1)

            /** The ceiling (ADR-0021): time 16, 2 GiB, 4 lanes. */
            val CEILING = Params(16, 2_097_152, 4)
        }
    }

    /** Why a blob was refused; mirrors the Go errors one for one. */
    sealed class SealedFileException(message: String) : Exception(message) {
        class Malformed(detail: String) : SealedFileException("sealedfile: malformed sealed-file blob: $detail")
        class UnknownMagic : SealedFileException("sealedfile: not a void-which-binds sealed file (unknown magic)")
        class UnknownKdf(id: Int) : SealedFileException("sealedfile: unknown KDF id 0x%02x".format(id))
        class BelowFloor(p: Params) : SealedFileException("sealedfile: KDF parameters are below the floor: $p")
        class AboveCeiling(p: Params) : SealedFileException("sealedfile: KDF parameters are above the ceiling: $p")

        /** A wrong passphrase, or a changed header or ciphertext: one error, no hint which. */
        class OpenFailed : SealedFileException("sealedfile: wrong passphrase, or the sealed file is damaged")
        class EmptyPassphrase : SealedFileException("sealedfile: the passphrase is empty")
    }

    /** The X25519 object's public key as `x25519:<hex>`, or null if there is none. Needs no passphrase. */
    val recipientId: String? get() = objects.firstOrNull { it.kind == Kind.X25519 }?.rendered()

    /** The named Ed25519 signer's public key as `ed25519:<hex>`, or null. Needs no passphrase. */
    fun signerId(name: String): String? = objects.firstOrNull { it.kind == Kind.ED25519 && it.name == name }?.rendered()

    /**
     * Derives the key from [passphrase] (UTF-8 bytes; the caller zeroes them) and opens the
     * seeds, checked against the clear header. Every failure to open is [SealedFileException.OpenFailed].
     */
    @Throws(SealedFileException::class)
    fun open(passphrase: ByteArray): Opened {
        if (passphrase.isEmpty()) throw SealedFileException.EmptyPassphrase()
        val key = deriveKey(passphrase, salt, params)
        val pt = try {
            XChaCha20Poly1305.decrypt(key, nonce, ad, ciphertext)
        } catch (_: GeneralSecurityException) {
            throw SealedFileException.OpenFailed()
        } finally {
            key.fill(0)
        }
        // Opaque on purpose, as in Go: a distinct error here would tell a crafted blob's
        // author that the passphrase they guessed was the one entered.
        if (!plaintextMatches(pt)) {
            pt.fill(0)
            throw SealedFileException.OpenFailed()
        }
        return Opened(this, pt)
    }

    /** [open] over a passphrase string (encoded as UTF-8, as Go's `[]byte(passphrase)`). */
    @Throws(SealedFileException::class)
    fun open(passphrase: String): Opened {
        val b = passphrase.encodeToByteArray()
        try {
            return open(b)
        } finally {
            b.fill(0)
        }
    }

    /**
     * The checks Go's `checkPlaintext` makes: the sealed objects repeat the clear ones, and each
     * seed backs its key.
     */
    private fun plaintextMatches(pt: ByteArray): Boolean {
        var off = 0
        for (e in objects) {
            val name = e.name.encodeToByteArray()
            if (pt.size < off + 2 + name.size + SEED_SIZE) return false
            if (pt[off] != e.kind.byte || (pt[off + 1].toInt() and 0xff) != name.size) return false
            if (!pt.copyOfRange(off + 2, off + 2 + name.size).contentEquals(name)) return false
            off += 2 + name.size
            val seed = pt.copyOfRange(off, off + SEED_SIZE)
            val pub = publicKey(e.kind, seed)
            seed.fill(0)
            if (!pub.contentEquals(e.publicKey)) return false
            off += SEED_SIZE
        }
        return off == pt.size
    }

    /**
     * An opened file: its seeds in memory until [close], which zeroes them (best effort). Each
     * accessor returns a copy; the caller zeroes that too.
     */
    class Opened internal constructor(private val file: SealedFile, private val plaintext: ByteArray) : AutoCloseable {
        private var closed = false

        /** The X25519 seed, or null if the file holds none. */
        fun x25519Seed(): ByteArray? = seedOf { it.kind == Kind.X25519 }

        /** The named Ed25519 seed, or null. */
        fun ed25519Seed(name: String): ByteArray? = seedOf { it.kind == Kind.ED25519 && it.name == name }

        private fun seedOf(match: (Entry) -> Boolean): ByteArray? {
            check(!closed) { "sealedfile: the opened file is closed" }
            var off = 0
            for (e in file.objects) {
                off += 2 + e.name.encodeToByteArray().size
                if (match(e)) return plaintext.copyOfRange(off, off + SEED_SIZE)
                off += SEED_SIZE
            }
            return null
        }

        override fun close() {
            plaintext.fill(0)
            closed = true
        }
    }

    companion object {
        const val MAGIC = "void-which-binds-sealed-file-v1\u0000"
        const val KDF_ARGON2ID: Byte = 0x01
        const val SEED_SIZE = 32
        const val SALT_SIZE = 32
        const val MAX_NAME_LEN = 255
        private const val PUB_SIZE = 32
        private val magicBytes = MAGIC.encodeToByteArray()
        private val fixedHeaderSize = magicBytes.size + 1 + 4 + 4 + 1 + SALT_SIZE + XChaCha20Poly1305.NONCE_SIZE + 1

        /**
         * Decodes a blob's clear header and checks everything that can be checked without the
         * passphrase, so every refusal here comes before any derivation.
         */
        @Throws(SealedFileException::class)
        fun parse(blob: ByteArray): SealedFile {
            if (blob.size < magicBytes.size || !blob.copyOfRange(0, magicBytes.size).contentEquals(magicBytes)) {
                throw SealedFileException.UnknownMagic()
            }
            if (blob.size < magicBytes.size + 1) throw SealedFileException.Malformed("truncated")
            val kdf = blob[magicBytes.size]
            if (kdf != KDF_ARGON2ID) throw SealedFileException.UnknownKdf(kdf.toInt() and 0xff)
            if (blob.size < fixedHeaderSize) throw SealedFileException.Malformed("truncated")
            var off = magicBytes.size + 1
            val params = Params(u32(blob, off), u32(blob, off + 4), blob[off + 8].toInt() and 0xff)
            checkParams(params)
            off += 9
            val salt = blob.copyOfRange(off, off + SALT_SIZE)
            off += SALT_SIZE
            val nonce = blob.copyOfRange(off, off + XChaCha20Poly1305.NONCE_SIZE)
            off += XChaCha20Poly1305.NONCE_SIZE
            val count = blob[off].toInt() and 0xff
            off++
            val entries = ArrayList<Entry>(count)
            val kinds = ArrayList<Byte>(count)
            val names = ArrayList<ByteArray>(count)
            repeat(count) {
                if (blob.size < off + 2) throw SealedFileException.Malformed("truncated")
                val k = blob[off]
                val nameLen = blob[off + 1].toInt() and 0xff
                off += 2
                if (blob.size < off + nameLen + PUB_SIZE) throw SealedFileException.Malformed("truncated")
                val name = blob.copyOfRange(off, off + nameLen)
                off += nameLen
                val pub = blob.copyOfRange(off, off + PUB_SIZE)
                off += PUB_SIZE
                kinds += k
                names += name
                val kind = Kind.entries.firstOrNull { it.byte == k }
                if (kind != null) entries += Entry(kind, name.decodeToString(), pub)
            }
            checkLayout(kinds, names)
            val want = plaintextLen(names) + XChaCha20Poly1305.TAG_SIZE
            val got = blob.size - off
            if (got < want) throw SealedFileException.Malformed("truncated (ciphertext $got bytes, want $want)")
            if (got > want) throw SealedFileException.Malformed("${got - want} trailing bytes")
            return SealedFile(params, entries, salt, nonce, blob.copyOfRange(0, off), blob.copyOfRange(off, blob.size))
        }

        /** Seals [objects] under [passphrase] at [params], with a fresh random salt and nonce. */
        @Throws(SealedFileException::class)
        fun seal(objects: List<Object>, passphrase: ByteArray, params: Params = Params.FLOOR): ByteArray {
            val rnd = SecureRandom()
            val salt = ByteArray(SALT_SIZE).also(rnd::nextBytes)
            val nonce = ByteArray(XChaCha20Poly1305.NONCE_SIZE).also(rnd::nextBytes)
            return seal(objects, passphrase, params, salt, nonce)
        }

        /** [seal] with the salt and nonce supplied: deterministic, for the byte-pinned vector. */
        internal fun seal(
            objects: List<Object>,
            passphrase: ByteArray,
            params: Params,
            salt: ByteArray,
            nonce: ByteArray,
        ): ByteArray {
            if (passphrase.isEmpty()) throw SealedFileException.EmptyPassphrase()
            checkParams(params)
            require(salt.size == SALT_SIZE && nonce.size == XChaCha20Poly1305.NONCE_SIZE) {
                "sealedfile: bad salt or nonce size"
            }
            val names = objects.map { it.name.encodeToByteArray() }
            checkLayout(objects.map { it.kind.byte }, names)
            val hdr = java.io.ByteArrayOutputStream()
            hdr.write(magicBytes)
            hdr.write(KDF_ARGON2ID.toInt())
            hdr.write(be32(params.time))
            hdr.write(be32(params.memoryKiB))
            hdr.write(params.parallelism)
            hdr.write(salt)
            hdr.write(nonce)
            hdr.write(objects.size)
            for ((i, o) in objects.withIndex()) {
                if (o.seed.size !=
                    SEED_SIZE
                ) {
                    throw SealedFileException.Malformed("a ${o.kind} seed is ${o.seed.size} bytes")
                }
                hdr.write(o.kind.byte.toInt())
                hdr.write(names[i].size)
                hdr.write(names[i])
                hdr.write(publicKey(o.kind, o.seed))
            }
            // The plaintext goes straight into one presized array, so the only seed copy
            // outside the caller's is this one, which the finally below zeroes.
            val ptBytes = ByteArray(names.sumOf { 2 + it.size + SEED_SIZE })
            var off = 0
            for ((i, o) in objects.withIndex()) {
                ptBytes[off++] = o.kind.byte
                ptBytes[off++] = names[i].size.toByte()
                names[i].copyInto(ptBytes, off)
                off += names[i].size
                o.seed.copyInto(ptBytes, off)
                off += SEED_SIZE
            }
            val ad = hdr.toByteArray()
            val key = deriveKey(passphrase, salt, params)
            try {
                return ad + XChaCha20Poly1305.encrypt(key, nonce, ad, ptBytes)
            } finally {
                key.fill(0)
                ptBytes.fill(0)
            }
        }
    }
}

/** The most objects one blob holds (the count is one byte). */
private const val MAX_OBJECTS = 255

private fun checkParams(p: SealedFile.Params) {
    val f = SealedFile.Params.FLOOR
    val c = SealedFile.Params.CEILING
    if (p.time < f.time || p.memoryKiB < f.memoryKiB || p.parallelism < f.parallelism) {
        throw SealedFile.SealedFileException.BelowFloor(p)
    }
    if (p.time > c.time || p.memoryKiB > c.memoryKiB || p.parallelism > c.parallelism) {
        throw SealedFile.SealedFileException.AboveCeiling(p)
    }
}

/**
 * Go's `checkLayout`: 1..255 objects; the X25519 one, if any, first and unnamed; Ed25519
 * ones named, UTF-8, unique.
 */
private fun checkLayout(kinds: List<Byte>, names: List<ByteArray>) {
    if (kinds.isEmpty()) throw SealedFile.SealedFileException.Malformed("no objects")
    if (kinds.size >
        MAX_OBJECTS
    ) {
        throw SealedFile.SealedFileException.Malformed("${kinds.size} objects, at most $MAX_OBJECTS")
    }
    val seen = HashSet<String>()
    for ((i, k) in kinds.withIndex()) {
        val name = names[i]
        when (k) {
            SealedFile.Kind.X25519.byte -> {
                if (i !=
                    0
                ) {
                    throw SealedFile.SealedFileException.Malformed(
                        "the x25519 object must come first, and there is at most one",
                    )
                }
                if (name.isNotEmpty()) throw SealedFile.SealedFileException.Malformed("the x25519 object has no name")
            }

            SealedFile.Kind.ED25519.byte -> {
                if (name.isEmpty() || name.size > SealedFile.MAX_NAME_LEN || !isValidUtf8(name)) {
                    throw SealedFile.SealedFileException.Malformed(
                        "an ed25519 object needs a UTF-8 name of 1..$SealedFile.MAX_NAME_LEN bytes",
                    )
                }
                if (!seen.add(
                        name.decodeToString(),
                    )
                ) {
                    throw SealedFile.SealedFileException.Malformed("two ed25519 objects with one name")
                }
            }

            else -> throw SealedFile.SealedFileException.Malformed("unknown key kind 0x%02x".format(k.toInt() and 0xff))
        }
    }
}

private fun plaintextLen(names: List<ByteArray>): Int = names.sumOf { 2 + it.size + SealedFile.SEED_SIZE }

private fun publicKey(kind: SealedFile.Kind, seed: ByteArray): ByteArray = when (kind) {
    SealedFile.Kind.X25519 -> X25519.scalarMultBase(seed)
    SealedFile.Kind.ED25519 -> Ed25519Group.publicKeyFromSeed(seed)
}

/** Go's `argon2.IDKey(passphrase, salt, time, memory, parallelism, 32)`: Argon2id v1.3, no secret, no AD. */
private fun deriveKey(passphrase: ByteArray, salt: ByteArray, p: SealedFile.Params): ByteArray {
    val gen = Argon2BytesGenerator()
    gen.init(
        Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(p.time.toInt())
            .withMemoryAsKB(p.memoryKiB.toInt())
            .withParallelism(p.parallelism)
            .withSalt(salt)
            .build(),
    )
    val out = ByteArray(XChaCha20Poly1305.KEY_SIZE)
    gen.generateBytes(passphrase, out)
    return out
}

private fun isValidUtf8(b: ByteArray): Boolean = try {
    Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b))
    true
} catch (_: java.nio.charset.CharacterCodingException) {
    false
}

private fun u32(b: ByteArray, o: Int): Long =
    ((b[o].toLong() and 0xff) shl 24) or ((b[o + 1].toLong() and 0xff) shl 16) or
        ((b[o + 2].toLong() and 0xff) shl 8) or (b[o + 3].toLong() and 0xff)

private fun be32(v: Long): ByteArray =
    byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
