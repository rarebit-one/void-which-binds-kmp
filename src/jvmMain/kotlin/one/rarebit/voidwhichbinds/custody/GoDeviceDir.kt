@file:Suppress("ReturnCount", "ThrowsCount")
// Ported from void-which-binds-go's device.Store: one refusal per Go error path, kept
// one-for-one with device/device.go and device/custody.go so a reviewer can diff them.

package one.rarebit.voidwhichbinds.custody

import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Labels
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.GoStrings
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * void-which-binds-go's per-user device directory (`device.Store`), read on the JVM for a
 * device whose keys are in a sealed file (ADR-0010): the same directory the reference CLI and
 * heyarr use, so a desktop app and the CLIs hold one device between them.
 *
 * - `device.json`: the record. A sealed device's says `"key_custody": "external"`.
 * - `device.sealed`: the sealed file ([SealedFile]), the X25519 seed and the `device` signer.
 * - `enrolment.cert`: the admitting op token. Present once the device is enrolled.
 * - `ops.jsonl`: the membership replica, one op token per line.
 *
 * Only a sealed device is read: a software device's seed files are the Go CLI's to use. As
 * Go's `loadCustody` does, [load] refuses a record the sealed file's public keys do not back
 * ([DeviceDirException.CustodyMismatch]): adopting either would silently change this device's
 * identity. Nothing here needs the passphrase; [keys] gives the private operations.
 * Pinned by void-which-binds-go's `device-dir` vector.
 *
 * [now] is unix seconds, for evaluating the enrolment and membership.
 */
class GoDeviceDir(val dir: Path, private val now: () -> Long = { Instant.now().epochSecond }) {
    /** The record, as `device.json` holds it. */
    @Suppress("LongParameterList") // Go's record struct, field for field
    class Record(
        val id: String,
        val name: String,
        val algorithm: String,
        /** `ed25519:<hex>`. */
        val publicKey: String,
        /** `x25519:<hex>`, or empty for a software device made before encryption keys. */
        val encryptionKey: String,
        val createdAt: Instant,
        /** `external` for a sealed device; null for a software one. */
        val keyCustody: String?,
    )

    /** A loaded device: its record, checked against its sealed file, and its enrolment. */
    class Device internal constructor(
        val record: Record,
        /** The admitting op, when it verifies and admits this device at load time. */
        val enrolmentCert: String?,
        /** The user this device authenticates as (`ed25519:<hex>`), when enrolled. */
        val enrolledUser: String?,
        /** The sealed file as read and checked against [record] by this load. */
        internal val sealed: SealedFile,
    ) {
        val enrolled: Boolean get() = enrolmentCert != null
    }

    sealed class DeviceDirException(message: String, cause: Throwable? = null) : Exception(message, cause) {
        /** No `device.json`: this machine has no device yet (Go `ErrNoDevice`). */
        class NoDevice(dir: Path) : DeviceDirException("device: no device in $dir yet")

        /** An unreadable record (Go `ErrMalformedKey`). */
        class Malformed(detail: String, cause: Throwable? = null) :
            DeviceDirException("device: $detail", cause)

        /** The sealed file does not back the record (Go `ErrCustodyMismatch`). */
        class CustodyMismatch(detail: String) :
            DeviceDirException("device: the custody keys do not back this device record: $detail")

        /** A sealed device whose sealed file is missing. */
        class NoSealedFile(path: Path) : DeviceDirException("device: the sealed keys at $path are missing")
    }

    val recordPath: Path get() = dir.resolve(RECORD_FILE)
    val sealedPath: Path get() = dir.resolve(SEALED_FILE)
    val certPath: Path get() = dir.resolve(CERT_FILE)
    val opsPath: Path get() = dir.resolve(OPS_FILE)

    /** Reads `device.json`, without checking it against anything. */
    @Throws(DeviceDirException::class, IOException::class)
    fun readRecord(): Record {
        val raw = try {
            Files.readString(recordPath)
        } catch (_: NoSuchFileException) {
            throw DeviceDirException.NoDevice(dir)
        }
        val m = try {
            MiniJson.parseObject(raw)
        } catch (e: IllegalArgumentException) {
            throw DeviceDirException.Malformed("$recordPath is not a device record", e)
        }
        fun str(k: String): String = when (val v = m[k]) {
            null -> ""
            is String -> v
            else -> throw DeviceDirException.Malformed("$recordPath: $k is not a string")
        }
        val createdAt = try {
            Instant.parse(str("created_at"))
        } catch (e: DateTimeParseException) {
            throw DeviceDirException.Malformed("$recordPath has an unreadable created_at", e)
        }
        return Record(
            id = str("id"),
            name = str("name"),
            algorithm = str("algorithm"),
            publicKey = str("public_key"),
            encryptionKey = str("encryption_key"),
            createdAt = createdAt,
            keyCustody = str("key_custody").ifEmpty { null },
        )
    }

    /** Parses `device.sealed`'s clear header. */
    @Throws(DeviceDirException::class, SealedFile.SealedFileException::class, IOException::class)
    fun sealedFile(): SealedFile {
        val blob = try {
            Files.readAllBytes(sealedPath)
        } catch (_: NoSuchFileException) {
            throw DeviceDirException.NoSealedFile(sealedPath)
        }
        return SealedFile.parse(blob)
    }

    /**
     * Loads the device: the record (Go's `load` order: the record, its `created_at`, its
     * custody), checked against the sealed file's public keys, and the enrolment cert,
     * re-verified now. A cert that does not verify or no longer admits this device reads as
     * not enrolled, not as an error, as Go's does.
     */
    @Throws(DeviceDirException::class, SealedFile.SealedFileException::class, IOException::class)
    fun load(): Device {
        val rec = readRecord()
        when (rec.keyCustody) {
            null -> throw DeviceDirException.CustodyMismatch(
                "$recordPath is a software device with seed files; only a sealed device is read here",
            )

            KEY_CUSTODY_EXTERNAL -> Unit

            else -> throw DeviceDirException.Malformed("$recordPath names an unknown key_custody \"${rec.keyCustody}\"")
        }
        parseKey(recordPath, rec.publicKey, Labels.ALG_ED25519, "public_key")
        parseKey(recordPath, rec.encryptionKey, Labels.ALG_X25519, "encryption_key (a custody device must record it)")
        val sealed = sealedFile()
        val signer = sealed.signerId(SealedDeviceKeys.DEVICE_SIGNER)
        if (signer != rec.publicKey) {
            throw DeviceDirException.CustodyMismatch(
                "$recordPath records ${rec.publicKey} and the custody signer is $signer",
            )
        }
        if (sealed.recipientId != rec.encryptionKey) {
            throw DeviceDirException.CustodyMismatch(
                "$recordPath records encryption key ${rec.encryptionKey} and the custody holder is " +
                    "${sealed.recipientId}",
            )
        }
        val (cert, user) = loadCert(rec.publicKey) ?: (null to null)
        return Device(rec, cert, user, sealed)
    }

    /** The custody keys of this device: [load] first, so they are the record's. */
    @Throws(DeviceDirException::class, SealedFile.SealedFileException::class, IOException::class)
    fun keys(passphrase: () -> ByteArray, ttlMillis: Long = SealedDeviceKeys.DEFAULT_TTL_MILLIS): SealedDeviceKeys {
        // The sealed file this load checked, not a second read: the directory is shared, and
        // a file swapped in between would be keys nobody checked against the record.
        return SealedDeviceKeys(load().sealed, passphrase, ttlMillis)
    }

    /** The membership replica, merged (Go `Store.Ops`): trimmed lines, blanks dropped. */
    @Throws(IOException::class)
    fun ops(): List<String> {
        val raw = try {
            Files.readString(opsPath)
        } catch (_: NoSuchFileException) {
            return emptyList()
        }
        return Membership.merge(raw.lines().map(GoStrings::trimSpace).filter { it.isNotEmpty() })
    }

    /**
     * Merges [ops] into the replica and writes it atomically (Go `RecordOps`): a temp file in
     * the directory, mode 0600, renamed over the old one.
     */
    @Throws(IOException::class)
    fun recordOps(ops: List<String>) = writeOps(Membership.merge(ops(), ops))

    /** The membership this device's enrolment evaluates to now (Go `Store.Membership`). */
    @Throws(Exception::class)
    fun membership(): Membership.View {
        val dev = load()
        val cert = checkNotNull(dev.enrolmentCert) { "device: this device holds no enrolment cert" }
        return Membership.evaluate(dev.enrolledUser!!, Membership.merge(ops(), listOf(cert)), now())
    }

    /** Go's `loadCert`: the cert, if it verifies, adds this device, and admits it now. */
    private fun loadCert(devicePub: String): Pair<String, String>? {
        val token = try {
            GoStrings.trimSpace(Files.readString(certPath))
        } catch (_: IOException) {
            return null
        }
        if (token.isEmpty()) return null
        return runCatching {
            val op = MembershipOp.verify(token)
            if (op.kind != MembershipOp.Kind.ADD || op.device != devicePub) return null
            val view = Membership.evaluate(op.user, Membership.merge(ops(), listOf(token)), now())
            if (!admits(view, op)) return null
            token to op.user
        }.getOrNull()
    }

    private fun writeOps(ops: List<String>) {
        createPrivateDir(dir)
        val tmp = Files.createTempFile(dir, ".ops-", ".tmp")
        try {
            restrict(tmp, PRIVATE_FILE)
            Files.writeString(tmp, ops.joinToString("") { it + "\n" })
            try {
                Files.move(tmp, opsPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, opsPath, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    companion object {
        const val RECORD_FILE = "device.json"

        /** heyarr's `devicekeys.SealedFileName`, which void-which-binds-go's CLI also opens. */
        const val SEALED_FILE = "device.sealed"
        const val CERT_FILE = "enrolment.cert"
        const val OPS_FILE = "ops.jsonl"

        /** The record's `key_custody` for a device whose keys are held in custody. */
        const val KEY_CUSTODY_EXTERNAL = "external"

        /** Overrides where the device directory is (Go `device.EnvDir`). */
        const val ENV_DIR = "VOID_WHICH_BINDS_DEVICE_DIR"

        /**
         * Go's `device.DefaultDir`: [ENV_DIR] if set, else `void-which-binds/device` under
         * `os.UserConfigDir` ($XDG_CONFIG_HOME or ~/.config on Linux, ~/Library/Application
         * Support on macOS, %AppData% on Windows).
         */
        fun defaultDir(
            env: (String) -> String? = System::getenv,
            osName: String = System.getProperty("os.name").orEmpty(),
            home: String = System.getProperty("user.home").orEmpty(),
        ): Path {
            env(ENV_DIR)?.trim()?.takeIf { it.isNotEmpty() }?.let { return Paths.get(it).normalize() }
            val base = when {
                osName.startsWith("Windows") -> env("AppData")?.takeIf { it.isNotEmpty() }
                    ?: error("device: %AppData% is not set (set $ENV_DIR to choose a directory)")

                osName.startsWith("Mac") -> Paths.get(home, "Library", "Application Support").toString()

                else -> env("XDG_CONFIG_HOME")?.takeIf { it.isNotEmpty() } ?: Paths.get(home, ".config").toString()
            }
            return Paths.get(base, "void-which-binds", "device")
        }
    }
}

private const val KEY_SIZE = 32
private const val PRIVATE_FILE = "rw-------"
private const val PRIVATE_DIR = "rwx------"

private fun parseKey(recordPath: Path, s: String, alg: String, field: String) {
    val ok = runCatching { KeyRef.parse(s) }.getOrNull()?.let { it.alg == alg && it.bytes.size == KEY_SIZE } == true
    if (!ok) throw GoDeviceDir.DeviceDirException.Malformed("$recordPath: $field is not an $alg key")
}

/** Go's `admitted`: the op is neither rejected nor ineffective, and its device is a member. */
private fun admits(view: Membership.View, op: MembershipOp): Boolean =
    op.hash !in view.rejected && op.hash !in view.ineffective && view.isMember(op.device)

private fun createPrivateDir(dir: Path) {
    if (Files.isDirectory(dir)) return
    try {
        Files.createDirectories(dir)
    } catch (_: FileAlreadyExistsException) {
        return
    }
    restrict(dir, PRIVATE_DIR)
}

private fun restrict(p: Path, perms: String) {
    if (p.fileSystem.supportedFileAttributeViews().contains("posix")) {
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(perms))
    }
}
