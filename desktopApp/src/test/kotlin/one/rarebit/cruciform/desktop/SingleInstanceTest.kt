package one.rarebit.cruciform.desktop

import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** One instance per user: the first claims and serves, a later launch forwards its link and exits. */
class SingleInstanceTest {
    private val dirs = mutableListOf<Path>()
    private val primaries = mutableListOf<AutoCloseable>()

    @AfterTest
    fun cleanUp() {
        primaries.forEach { runCatching { it.close() } }
        dirs.forEach { it.toFile().deleteRecursively() }
    }

    private fun dir(): Path = Files.createTempDirectory(
        "cruciform-instance",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    ).also(dirs::add)

    private fun serve(dir: Path): Pair<SingleInstance.Primary, LinkedBlockingQueue<String>> {
        val primary = assertIs<SingleInstance.Primary>(SingleInstance(dir).claim(""))
        primaries += primary
        val got = LinkedBlockingQueue<String>()
        primary.serve { got.put(it) }
        return primary to got
    }

    @Test
    fun aLaterLaunchHandsItsLinkToTheRunningOne() {
        val d = dir()
        val (_, got) = serve(d)
        val link = "void-which-binds:login?rp=https%3A%2F%2Fsite.example&id=abc"
        assertEquals(SingleInstance.Forwarded, SingleInstance(d).claim(link))
        assertEquals(link, got.poll(5, TimeUnit.SECONDS))
        // A plain launch (no link) asks the running window to come to the front.
        assertEquals(SingleInstance.Forwarded, SingleInstance(d).claim(""))
        assertEquals("", got.poll(5, TimeUnit.SECONDS))
    }

    @Test
    fun theSocketAndLockAreOwnerOnly() {
        val d = dir()
        serve(d)
        for (f in listOf(SingleInstance.SOCKET_FILE, SingleInstance.LOCK_FILE)) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(d.resolve(f))), f)
        }
    }

    @Test
    fun onlyLinksAndRaiseRequestsAreActedOnAndOversizeIsDropped() {
        val d = dir()
        val (_, got) = serve(d)
        fun send(bytes: ByteArray) = SocketChannel.open(StandardProtocolFamily.UNIX).use { ch ->
            ch.connect(UnixDomainSocketAddress.of(d.resolve(SingleInstance.SOCKET_FILE)))
            val b = ByteBuffer.wrap(bytes)
            while (b.hasRemaining()) ch.write(b)
        }
        send("https://evil.example".encodeToByteArray())
        send(("void-which-binds:login?" + "x".repeat(SingleInstance.MAX_MESSAGE_BYTES)).encodeToByteArray())
        send("  void-which-binds:approve?h=abc \n".encodeToByteArray())
        assertEquals("void-which-binds:approve?h=abc", got.poll(5, TimeUnit.SECONDS))
        assertNull(got.poll(300, TimeUnit.MILLISECONDS))
        assertNull(SingleInstance.accepted("file:///etc/passwd"))
    }

    @Test
    fun aCrashedInstancesSocketIsReplacedNotTrusted() {
        val d = dir()
        Files.writeString(d.resolve(SingleInstance.SOCKET_FILE), "stale") // left by a crash; no lock held
        val (_, got) = serve(d)
        assertEquals(SingleInstance.Forwarded, SingleInstance(d).claim("void-which-binds:approve?h=1"))
        assertEquals("void-which-binds:approve?h=1", got.poll(5, TimeUnit.SECONDS))
    }

    @Test
    fun theNextLaunchAfterTheInstanceClosesBecomesTheInstance() {
        val d = dir()
        val (primary, _) = serve(d)
        primary.close()
        assertIs<SingleInstance.Primary>(SingleInstance(d).claim("")).also(primaries::add)
    }

    @Test
    fun aLaunchWaitingOnAnInstanceThatExitsTakesTheLock() {
        val d = dir()
        val held = assertIs<SingleInstance.Primary>(SingleInstance(d).claim("")) // locked, never serves
        // The holder exits while the next launch is still waiting to forward.
        Thread {
            Thread.sleep(300)
            held.close()
        }.start()
        assertIs<SingleInstance.Primary>(SingleInstance(d).claim("", waitMillis = 5_000)).also(primaries::add)
    }

    @Test
    fun aRunningInstanceThatCannotBeReachedIsNotWaitedOnForever() {
        val d = dir()
        val held = assertIs<SingleInstance.Primary>(SingleInstance(d).claim("")) // locked, never serves
        primaries += held
        val t0 = System.nanoTime()
        assertEquals(SingleInstance.Unreachable, SingleInstance(d).claim("", waitMillis = 300))
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 3_000)
    }

    @Test
    fun aDirectoryOthersCanReachIsNotTrusted() {
        val d = dir()
        Files.setPosixFilePermissions(d, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertEquals(SingleInstance.Untrusted, SingleInstance(d).claim("void-which-binds:login?id=1"))
        assertTrue(Files.notExists(d.resolve(SingleInstance.SOCKET_FILE)))
    }

    @Test
    fun aSymlinkInPlaceOfTheDirectoryIsNotTrusted() {
        val target = dir()
        val link = Files.createSymbolicLink(dir().resolve("runtime"), target)
        assertEquals(SingleInstance.Untrusted, SingleInstance(link).claim(""))
    }

    @Test
    fun aMissingFallbackIsCreatedOwnerOnlyAndTrusted() {
        val d = dir().resolve("fallback")
        assertIs<SingleInstance.Primary>(SingleInstance(d).claim("")).also(primaries::add)
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(d)))
    }

    @Test
    fun theRuntimeDirIsXdgsElseAPerUserTempDir() {
        assertEquals(
            Path.of("/run/user/1000"),
            SingleInstance.defaultDir {
                if (it ==
                    "XDG_RUNTIME_DIR"
                ) {
                    "/run/user/1000"
                } else {
                    null
                }
            },
        )
        assertTrue(SingleInstance.defaultDir { null }.fileName.toString().startsWith("cruciform-desktop-"))
    }
}
