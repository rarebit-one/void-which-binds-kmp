package one.rarebit.cruciform.desktop

import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.custody.GoDeviceDir
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/**
 * Where this desktop reaches the network. Nothing is built in: a private endpoint must never
 * ship in the app, so a fresh install has none and says so where it needs one.
 *
 * - [relay]: the pairing relay "Add a device" mints its invites through.
 * - [membershipRps]: relying parties serving `POST /membership/{usr}`, told of an add or a
 *   remove at once (best effort; the ops also travel with every sign-in).
 * - [brokers]: action-approval brokers (ADR-0019) this device fetches approvals from. A
 *   broker's audience is its origin.
 */
data class DesktopSettings(
    val relay: String = "",
    val membershipRps: List<String> = emptyList(),
    val brokers: List<String> = emptyList(),
) {
    /** Reads and writes the settings as JSON in [path] (0600 where the filesystem allows). */
    class Store(val path: Path) {
        fun load(): DesktopSettings {
            val raw = try {
                Files.readString(path)
            } catch (_: NoSuchFileException) {
                return DesktopSettings()
            }
            val m = MiniJson.parseObject(raw)
            fun list(k: String) = (m[k] as? List<*>).orEmpty().filterIsInstance<String>().map(String::trim)
                .filter(String::isNotEmpty)
            return DesktopSettings((m["relay"] as? String).orEmpty().trim(), list("membership_rps"), list("brokers"))
        }

        fun save(s: DesktopSettings) {
            Files.createDirectories(path.parent)
            val json = MiniJson.encodeObject(
                listOf("relay" to s.relay, "membership_rps" to s.membershipRps, "brokers" to s.brokers),
            )
            val tmp = Files.createTempFile(path.parent, ".settings-", ".tmp")
            try {
                if (tmp.fileSystem.supportedFileAttributeViews().contains("posix")) {
                    Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"))
                }
                Files.writeString(tmp, json + "\n")
                try {
                    Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
                } catch (_: AtomicMoveNotSupportedException) {
                    Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING)
                }
            } finally {
                Files.deleteIfExists(tmp)
            }
        }

        companion object {
            /**
             * `cruciform-desktop/settings.json` in the user's config directory, the one Go's
             * `os.UserConfigDir` names (beside `void-which-binds/`), whatever
             * `VOID_WHICH_BINDS_DEVICE_DIR` says.
             */
            fun default(): Store {
                val deviceDir = GoDeviceDir.defaultDir(env = { k ->
                    if (k ==
                        GoDeviceDir.ENV_DIR
                    ) {
                        null
                    } else {
                        System.getenv(k)
                    }
                })
                val base = deviceDir.parent?.parent ?: Paths.get(".")
                return Store(base.resolve("cruciform-desktop").resolve("settings.json"))
            }
        }
    }
}
