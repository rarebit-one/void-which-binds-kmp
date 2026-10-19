package one.rarebit.cruciform.desktop

import java.io.IOException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermissions

/**
 * One Cruciform per user. The first launch holds a lock file and listens on a Unix socket
 * beside it; a later launch (a browser opening a `void-which-binds:` link) hands its link to
 * that one and exits, instead of opening a second window over the same device.
 *
 * Both files live in [dir], the user's runtime directory ($XDG_RUNTIME_DIR, 0700). The lock,
 * not the socket, decides who is first: a crashed instance releases it with its process, so
 * a stale socket left behind is simply replaced. What is forwarded is only ever a link for
 * the UI to show; acting on it still needs the person's click, as from the command line.
 */
class SingleInstance(private val dir: Path) {
    private val lockPath: Path = dir.resolve(LOCK_FILE)
    private val socketPath: Path = dir.resolve(SOCKET_FILE)

    /** The outcome of [claim]. */
    sealed interface Claim

    /** This process is the instance: [serve] its socket. */
    inner class Primary internal constructor(private val lockChannel: FileChannel, private val lock: FileLock) :
        Claim,
        AutoCloseable {
        private var server: ServerSocketChannel? = null

        /**
         * Listens for forwarded messages on a daemon thread, calling [onMessage] with each
         * (an empty string means "come to the front"; otherwise a `void-which-binds:` link).
         */
        fun serve(onMessage: (String) -> Unit) {
            Files.deleteIfExists(socketPath) // a crashed instance's socket; the lock is ours
            val ch = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
            ch.bind(UnixDomainSocketAddress.of(socketPath))
            restrict(socketPath)
            server = ch
            Thread({ acceptLoop(ch, onMessage) }, "cruciform-single-instance").apply {
                isDaemon = true
                start()
            }
        }

        override fun close() {
            runCatching { server?.close() }
            runCatching { Files.deleteIfExists(socketPath) }
            runCatching { lock.release() }
            runCatching { lockChannel.close() }
        }
    }

    /** Another instance is running and took [message]: this process should exit. */
    data object Forwarded : Claim

    /** Another instance holds the lock but could not be reached: run alone rather than vanish. */
    data object Unreachable : Claim

    /**
     * [dir] is not this user's private directory (a symlink, another owner, or reachable by
     * others; a predictable fallback in /tmp can be pre-created by another account): no
     * handoff at all, so nothing forwarded can be captured. Run alone.
     */
    data object Untrusted : Claim

    /**
     * Claims the instance, or forwards [message] to the one that has it. A launch that cannot
     * reach the running instance within [waitMillis] (it may still be starting) runs alone.
     */
    fun claim(message: String, waitMillis: Long = DEFAULT_WAIT_MILLIS): Claim =
        if (privateDir()) lockOrForward(message, waitMillis) else Untrusted

    /** Creates the fallback owner-only if missing, then checks [dir], whoever made it. */
    private fun privateDir(): Boolean {
        try {
            // Only the fallback (no $XDG_RUNTIME_DIR) is ever created here.
            Files.createDirectory(
                dir,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
            )
        } catch (_: FileAlreadyExistsException) {
            // Existing: trusted only if it passes the check.
        }
        return isPrivate(dir)
    }

    /**
     * Takes the lock, or hands [message] to the instance that holds it. Both are retried
     * until the deadline: the holder may still be starting its socket, or may exit meanwhile,
     * and then this launch must take the lock rather than run beside the next one.
     */
    private fun lockOrForward(message: String, waitMillis: Long): Claim {
        val deadline = System.nanoTime() + waitMillis * NANOS_PER_MILLI
        var claim: Claim? = tryLock() ?: Forwarded.takeIf { forward(message) }
        while (claim == null && System.nanoTime() - deadline < 0) {
            Thread.sleep(RETRY_MILLIS)
            claim = tryLock() ?: Forwarded.takeIf { forward(message) }
        }
        return claim ?: Unreachable
    }

    private fun tryLock(): Primary? {
        val channel = FileChannel.open(lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        val lock = try {
            channel.tryLock()
        } catch (_: OverlappingFileLockException) {
            null // held by this JVM already (a test, or a second claim): not ours
        }
        if (lock == null) {
            channel.close()
            return null
        }
        restrict(lockPath)
        return Primary(channel, lock)
    }

    private fun forward(message: String): Boolean = try {
        SocketChannel.open(UnixDomainSocketAddress.of(socketPath)).use { ch ->
            val bytes = ByteBuffer.wrap(message.encodeToByteArray())
            while (bytes.hasRemaining()) ch.write(bytes)
            ch.shutdownOutput()
        }
        true
    } catch (_: IOException) {
        false // not listening yet, or gone
    }

    private fun acceptLoop(server: ServerSocketChannel, onMessage: (String) -> Unit) {
        while (server.isOpen) {
            val client = try {
                server.accept()
            } catch (_: IOException) {
                return // closed
            }
            val message = runCatching { client.use { readCapped(it) } }.getOrNull() ?: continue
            accepted(message)?.let(onMessage)
        }
    }

    private fun readCapped(ch: SocketChannel): String? {
        val buf = ByteBuffer.allocate(MAX_MESSAGE_BYTES + 1)
        while (ch.read(buf) >= 0) {
            if (!buf.hasRemaining()) return null // over the cap: dropped whole
        }
        return String(buf.array(), 0, buf.position(), Charsets.UTF_8)
    }

    companion object {
        const val LOCK_FILE = "cruciform-desktop.lock"
        const val SOCKET_FILE = "cruciform-desktop.sock"

        /** A link is a few hundred bytes; anything this long is not one. */
        const val MAX_MESSAGE_BYTES = 8 * 1024

        private const val DEFAULT_WAIT_MILLIS = 3_000L
        private const val RETRY_MILLIS = 100L
        private const val NANOS_PER_MILLI = 1_000_000L

        /**
         * What the running instance acts on: an empty message (come to the front) or a
         * `void-which-binds:` link, trimmed. Anything else is ignored.
         */
        fun accepted(message: String): String? {
            val m = message.trim()
            return m.takeIf { it.isEmpty() || it.startsWith("void-which-binds:") }
        }

        /**
         * Whether [dir] is a real directory (not a symlink) owned by this process's user with
         * no group or other access, read without following links.
         */
        fun isPrivate(dir: Path): Boolean {
            val attrs = runCatching {
                Files.readAttributes(dir, PosixFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            }.getOrNull() ?: return false
            val me = dir.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name"))
            val shared = attrs.permissions().any { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") }
            return attrs.isDirectory && !attrs.isSymbolicLink && attrs.owner() == me && !shared
        }

        /** $XDG_RUNTIME_DIR, else a per-user directory under the temp dir. */
        fun defaultDir(env: (String) -> String? = System::getenv): Path =
            env("XDG_RUNTIME_DIR")?.takeIf { it.isNotBlank() }?.let { Paths.get(it) }
                ?: Paths.get(
                    System.getProperty("java.io.tmpdir"),
                    "cruciform-desktop-" + System.getProperty("user.name"),
                )

        private fun restrict(p: Path) {
            if (p.fileSystem.supportedFileAttributeViews().contains("posix")) {
                Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"))
            }
        }
    }
}
