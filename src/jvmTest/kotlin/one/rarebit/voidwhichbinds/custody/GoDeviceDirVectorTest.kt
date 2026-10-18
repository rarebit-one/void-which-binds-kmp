package one.rarebit.voidwhichbinds.custody

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * void-which-binds-go's `device-dir` vector (copied verbatim, pinned by
 * VOID_WHICH_BINDS_GO_REF): a custody device's directory as `device.Store` writes it. The
 * Kotlin reader loads it as Go does, reads the same replica and membership, and refuses or
 * ignores each edited file as Go does.
 */
class GoDeviceDirVectorTest {

    private val v: Map<String, Any> by lazy {
        val raw = javaClass.getResourceAsStream("/vectors/device-dir/sealed-enrolled.json")
            ?.readBytes()?.decodeToString() ?: error("vectors/device-dir/sealed-enrolled.json missing")
        MiniJson.parseObject(raw)
    }

    @Suppress("UNCHECKED_CAST")
    private fun obj(m: Any?): Map<String, Any> = m as Map<String, Any>

    @Suppress("UNCHECKED_CAST")
    private fun strings(m: Any?): List<String> = m as List<String>

    private val now: Long by lazy { Instant.parse(v["now"] as String).epochSecond }
    private val sealedName: String by lazy { v["sealed_file_name"] as String }

    private val dirs = mutableListOf<Path>()

    @AfterTest
    fun cleanUp() {
        dirs.forEach { d -> d.toFile().deleteRecursively() }
    }

    /** The vector's files in a fresh directory, [file] replaced by [contents] if given. */
    private fun write(file: String? = null, contents: String? = null): GoDeviceDir {
        val dir = Files.createTempDirectory("device-dir").also(dirs::add)
        for ((name, body) in obj(v["files"])) {
            val bytes = when {
                name == file -> contents!!.encodeToByteArray()
                name == sealedName -> Hex.decode(body as String)
                else -> (body as String).encodeToByteArray()
            }
            Files.write(dir.resolve(name), bytes)
        }
        return GoDeviceDir(dir) { now }
    }

    @Test
    fun theLayoutIsGos() {
        assertEquals(GoDeviceDir.SEALED_FILE, sealedName)
        assertEquals(
            setOf(GoDeviceDir.RECORD_FILE, GoDeviceDir.SEALED_FILE, GoDeviceDir.CERT_FILE, GoDeviceDir.OPS_FILE),
            obj(v["files"]).keys,
        )
    }

    @Test
    fun loadsTheDeviceAsGoDoes() {
        val dir = write()
        val dev = dir.load()
        val want = obj(v["device"])
        val r = dev.record
        assertEquals(want["id"], r.id)
        assertEquals(want["name"], r.name)
        assertEquals(want["algorithm"], r.algorithm)
        assertEquals(want["public_key"], r.publicKey)
        assertEquals(want["encryption_key"], r.encryptionKey)
        assertEquals(Instant.parse(want["created_at"] as String), r.createdAt)
        assertEquals(want["key_custody"], r.keyCustody)
        assertEquals(v["enrolment"], if (dev.enrolled) "enrolled" else "not_enrolled")
        assertEquals(v["enrolled_user"], dev.enrolledUser)
        assertEquals(strings(v["ops"]), dir.ops())
        assertEquals(strings(v["members"]), dir.membership().members.keys.sorted())
    }

    @Test
    fun theSealedFileBacksTheRecordWithoutThePassphrase() {
        val dir = write()
        var asked = 0
        val keys = dir.keys({
            asked++
            "unused".encodeToByteArray()
        })
        assertEquals(obj(v["device"])["public_key"], keys.deviceId.render())
        assertEquals(0, asked)
    }

    @Test
    fun eachEditedFileIsRefusedOrIgnoredAsGoDoes() {
        @Suppress("UNCHECKED_CAST")
        val rows = v["refusals"] as List<Map<String, Any>>
        assertTrue(rows.isNotEmpty())
        for (r in rows) {
            val name = r["name"] as String
            val dir = write(r["file"] as String, r["contents"] as String)
            when (val err = r["error"] as String?) {
                "custody-mismatch" -> assertFailsWith<GoDeviceDir.DeviceDirException.CustodyMismatch>(name) {
                    dir.load()
                }

                "malformed" -> assertFailsWith<GoDeviceDir.DeviceDirException.Malformed>(name) { dir.load() }

                null -> assertEquals(r["enrolment"], if (dir.load().enrolled) "enrolled" else "not_enrolled", name)

                else -> error("$name: unknown error kind $err")
            }
        }
    }

    @Test
    fun recordOpsMergesAndWritesThePrivateReplicaAtomically() {
        val dir = write(GoDeviceDir.OPS_FILE, "")
        val ops = strings(v["ops"])
        dir.recordOps(listOf(ops[0]))
        dir.recordOps(listOf(ops[1], ops[0], ""))
        assertEquals(ops, dir.ops())
        assertEquals(ops.joinToString("") { it + "\n" }, Files.readString(dir.opsPath))
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.opsPath)))
        val left = Files.list(dir.dir).use { s -> s.map { it.fileName.toString() }.toList() }
        assertTrue(left.none { it.startsWith(".ops-") }, "a temp file was left: $left")
    }

    @Test
    fun keysAreTheSealedFileLoadChecked() {
        val dir = write()
        val keys = dir.keys({ "unused".encodeToByteArray() })
        // Swapped after the check: the keys already in hand are the checked ones.
        Files.write(dir.sealedPath, ByteArray(0))
        assertEquals(obj(v["device"])["public_key"], keys.deviceId.render())
        assertEquals(obj(v["device"])["encryption_key"], KeyRef.x25519(keys.encPublicKey).render())
    }

    @Test
    fun aMissingDirectoryOrSealedFileIsSaid() {
        val empty = GoDeviceDir(Files.createTempDirectory("device-dir").also(dirs::add)) { now }
        assertFailsWith<GoDeviceDir.DeviceDirException.NoDevice> { empty.load() }
        val dir = write()
        Files.delete(dir.sealedPath)
        assertFailsWith<GoDeviceDir.DeviceDirException.NoSealedFile> { dir.load() }
    }

    @Test
    fun theReplicasOpsWereSignedThroughTheSealedSigner() {
        // The second op is the device's own: its `by` is the device key, and its signature
        // verifies under it, so the sealed signer Go used is the one this reader reports.
        val device = obj(v["device"])["public_key"] as String
        val own = strings(v["ops"]).map { MembershipOp.verify(it, Ed25519Engine.verifier()) }.filter { it.by == device }
        assertEquals(1, own.size)
    }

    @Test
    fun defaultDirIsGos() {
        val env = mapOf("XDG_CONFIG_HOME" to "/cfg")
        assertEquals(
            Path.of("/cfg/void-which-binds/device"),
            GoDeviceDir.defaultDir(env::get, "Linux", "/home/u"),
        )
        assertEquals(
            Path.of("/home/u/.config/void-which-binds/device"),
            GoDeviceDir.defaultDir({ null }, "Linux", "/home/u"),
        )
        assertEquals(
            Path.of("/home/u/Library/Application Support/void-which-binds/device"),
            GoDeviceDir.defaultDir({ null }, "Mac OS X", "/home/u"),
        )
        assertEquals(
            Path.of("/elsewhere"),
            GoDeviceDir.defaultDir(mapOf(GoDeviceDir.ENV_DIR to " /elsewhere/ ")::get, "Linux", "/home/u"),
        )
    }
}
