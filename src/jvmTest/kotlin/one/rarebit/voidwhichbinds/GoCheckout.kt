package one.rarebit.voidwhichbinds

import java.io.File

/**
 * The local void-which-binds-go checkout the live-Go interop tests build their CLI
 * from: `$VOID_WHICH_BINDS_GO_DIR`, else `~/Workspace/rarebit-one/void-which-binds-go`,
 * else the pre-rename directory name until the local checkout is renamed (ADR-0013 R1).
 * It must be a gen2 (v0.19+, ADR-0022) checkout: gen1 Go cannot interop with this
 * library. When none exists (CI), the interop tests are skipped, not failed.
 */
internal object GoCheckout {
    private val workspace = File(System.getProperty("user.home"), "Workspace/rarebit-one")

    val dir: File =
        System.getenv("VOID_WHICH_BINDS_GO_DIR")?.takeIf { it.isNotBlank() }?.let(::File)
            ?: listOf("void-which-binds-go", "voidbind-go") // k0:keep: a local checkout dir name, not a wire string
                .map { File(workspace, it) }
                .firstOrNull { it.isDirectory }
            ?: File(workspace, "void-which-binds-go")

    /** The CLI package (`cmd/void-which-binds` since void-which-binds-go v0.18.0). */
    const val CLI_PACKAGE: String = "./cmd/void-which-binds"
}
