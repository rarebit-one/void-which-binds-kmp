package one.rarebit.voidwhichbinds

import java.io.File

/**
 * The local void-which-binds-go checkout the live-Go interop tests build their CLI
 * from: `$VOID_WHICH_BINDS_GO_DIR`, else `~/Workspace/rarebit-one/void-which-binds-go`,
 * else the pre-rename directory name until the local checkout is renamed (ADR-0013 R1).
 * When none exists (CI), the interop tests are skipped, not failed.
 */
internal object GoCheckout {
    private val workspace = File(System.getProperty("user.home"), "Workspace/rarebit-one")

    val dir: File =
        System.getenv("VOID_WHICH_BINDS_GO_DIR")?.takeIf { it.isNotBlank() }?.let(::File)
            ?: listOf("void-which-binds-go", "voidbind-go") // k0:keep (ADR-0013 legacy dir name)
                .map { File(workspace, it) }
                .firstOrNull { it.isDirectory }
            ?: File(workspace, "void-which-binds-go")

    /** The CLI package, renamed at void-which-binds-go v0.18.0; older checkouts keep the gen1 path. */
    val cliPackage: String
        get() = if (File(dir, "cmd/void-which-binds").isDirectory) "./cmd/void-which-binds" else LEGACY_CLI_PACKAGE

    private const val LEGACY_CLI_PACKAGE = "./cmd/voidbind" // k0:keep (ADR-0013 legacy)
}
