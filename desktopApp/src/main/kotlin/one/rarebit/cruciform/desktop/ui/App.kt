package one.rarebit.cruciform.desktop.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import one.rarebit.cruciform.desktop.DesktopEngine
import one.rarebit.cruciform.desktop.DesktopSettings
import one.rarebit.voidwhichbinds.approval.OpenedApproval
import one.rarebit.voidwhichbinds.custody.GoDeviceDir
import one.rarebit.voidwhichbinds.flow.LoginApproval
import java.net.URI
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

enum class Screen(val label: String) {
    OVERVIEW("This device"),
    DEVICES("Devices"),
    ADD("Add a device"),
    SIGN_IN("Sign in"),
    APPROVALS("Approvals"),
    SETTINGS("Settings"),
}

/**
 * Runs blocking engine work off the UI thread. A [DesktopEngine.LockedException] opens the
 * unlock dialog and, once unlocked, runs the same work again; any other failure is shown.
 */
class Runner(private val scope: CoroutineScope) {
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
    var unlockThen by mutableStateOf<(() -> Unit)?>(null)
    var revision by mutableStateOf(0)
        private set

    private var job: Job? = null

    // The UI's one error boundary: any failure of the work is shown, never thrown at Compose.
    @Suppress("TooGenericExceptionCaught")
    fun <T> run(work: () -> T, onDone: (T) -> Unit = {}) {
        if (busy) return
        busy = true
        error = null
        job = scope.launch {
            // Interruptible, so cancel() stops a blocking relay poll (its sleep) at once.
            val r = try {
                Result.success(runInterruptible(Dispatchers.IO, work))
            } catch (e: CancellationException) {
                busy = false
                revision++
                throw e
            } catch (e: Exception) {
                Result.failure(e)
            }
            busy = false
            revision++
            r.onSuccess(onDone).onFailure { e ->
                if (e is DesktopEngine.LockedException) unlockThen = { run(work, onDone) } else error = describe(e)
            }
        }
    }

    /** Stops the work in progress (a pairing wait); its result, if any, is dropped. */
    fun cancel() {
        job?.cancel()
    }

    fun changed() {
        revision++
    }
}

fun describe(e: Throwable): String = when (e) {
    is GoDeviceDir.DeviceDirException.NoDevice -> "There is no device on this machine yet. ${e.message}"

    is GoDeviceDir.DeviceDirException.CustodyMismatch ->
        "This device's sealed keys don't match its record, so it won't be used. ${e.message}"

    else -> e.message ?: e::class.simpleName ?: "Something went wrong."
}

@Composable
fun App(engine: DesktopEngine, state: AppState) {
    val scope = rememberCoroutineScope()
    val runner = remember { Runner(scope) }
    val pairing = remember { PairingState() }
    // The unlock hold lapses on its own (and is wiped then): re-read the state now and then,
    // so a screen never says "Unlocked" about keys that are gone.
    LaunchedEffect(Unit) {
        while (true) {
            kotlinx.coroutines.delay(STATE_REFRESH_MILLIS)
            if (!runner.busy) runner.changed()
        }
    }
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Row(Modifier.fillMaxSize()) {
                NavigationRail {
                    Screen.entries.forEachIndexed { i, s ->
                        // Material's own focus mark is a faint state layer: ring the focused
                        // item so keyboard navigation can be seen.
                        val interaction = remember { MutableInteractionSource() }
                        val focused by interaction.collectIsFocusedAsState()
                        NavigationRailItem(
                            selected = s == state.screen,
                            onClick = { state.screen = s },
                            icon = {},
                            label = { Text(s.label) },
                            interactionSource = interaction,
                            modifier = Modifier
                                .semantics { contentDescription = "${s.label} (Ctrl+${i + 1})" }
                                .then(
                                    if (focused) {
                                        Modifier.border(
                                            2.dp,
                                            MaterialTheme.colorScheme.primary,
                                            RoundedCornerShape(12.dp),
                                        )
                                    } else {
                                        Modifier
                                    },
                                ),
                        )
                    }
                }
                Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState())) {
                    NotHardwareBacked()
                    Spacer(Modifier.height(16.dp))
                    when (state.screen) {
                        Screen.OVERVIEW -> OverviewScreen(engine, runner)
                        Screen.DEVICES -> DevicesScreen(engine, runner)
                        Screen.ADD -> AddDeviceScreen(engine, runner, pairing)
                        Screen.SIGN_IN -> SignInScreen(engine, runner, state.incoming)
                        Screen.APPROVALS -> ApprovalsScreen(engine, runner, state.incoming)
                        Screen.SETTINGS -> SettingsScreen(engine, runner)
                    }
                    runner.error?.let {
                        Spacer(Modifier.height(16.dp))
                        Text(it, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            runner.unlockThen?.let { then ->
                UnlockDialog(
                    engine,
                    onUnlocked = {
                        runner.unlockThen = null
                        runner.changed()
                        then()
                    },
                    onDismiss = {
                        runner.unlockThen = null
                        runner.error = "Locked: nothing was signed."
                    },
                )
            }
        }
    }
}

/** The posture, stated where every screen shows it. */
@Composable
private fun NotHardwareBacked() {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
        Text(
            "Not hardware-backed. This device's keys are in a passphrase-sealed file, not a secure " +
                "element: a copy of the file is useless without the passphrase, but software running " +
                "as you can capture the passphrase or read the keys while they are unlocked.",
            Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun Heading(text: String) {
    Text(text, style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(12.dp))
}

@Composable
private fun Field(label: String, value: String, mono: Boolean = false) {
    Column(Modifier.padding(vertical = 4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        SelectionContainer {
            Text(value, fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default)
        }
    }
}

/**
 * Timestamps come from sites and signed ops, so any Long can arrive: one outside what
 * [Instant] holds is shown as the raw number, never thrown during composition.
 */
private fun formatUnix(unix: Long, format: (Instant) -> String): String =
    runCatching { format(Instant.ofEpochSecond(unix)) }.getOrElse { "$unix (unix seconds, out of range)" }

private fun date(unix: Long): String =
    formatUnix(unix) { DateTimeFormatter.ofPattern("d MMM yyyy").withZone(ZoneId.systemDefault()).format(it) }

internal fun timestamp(unix: Long): String = formatUnix(unix) { it.toString() }

private fun host(url: String): String = runCatching { URI(url).host }.getOrNull() ?: url

@Composable
private fun OverviewScreen(engine: DesktopEngine, runner: Runner) {
    var overview by remember { mutableStateOf<DesktopEngine.Overview?>(null) }
    LaunchedEffect(runner.revision) {
        overview = withContext(Dispatchers.IO) {
            runCatching { engine.overview() }.onFailure { runner.error = describe(it) }.getOrNull()
        }
    }
    Heading("This device")
    val o = overview ?: return
    Field("Name", o.name)
    Field("Device key", o.deviceId, mono = true)
    if (o.enrolled) {
        Field("Signs in as (fingerprint)", o.userFingerprint.orEmpty(), mono = true)
        Field("Identity", o.userId.orEmpty(), mono = true)
    } else {
        Text("Not enrolled with an identity. Add it from a phone or the void-which-binds CLI.")
    }
    Field("Keys", if (engine.isUnlocked) "Unlocked" else "Locked")
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (engine.isUnlocked) {
            OutlinedButton(onClick = {
                engine.lock()
                runner.changed()
            }) { Text("Lock now") }
        } else {
            Button(onClick = { runner.unlockThen = {} }) { Text("Unlock") }
        }
    }
    Spacer(Modifier.height(8.dp))
    Text("Device directory: ${engine.dir.dir}", style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun DevicesScreen(engine: DesktopEngine, runner: Runner) {
    var overview by remember { mutableStateOf<DesktopEngine.Overview?>(null) }
    var confirm by remember { mutableStateOf<DesktopEngine.Member?>(null) }
    LaunchedEffect(runner.revision) {
        overview = withContext(Dispatchers.IO) {
            runCatching { engine.overview() }.onFailure { runner.error = describe(it) }.getOrNull()
        }
    }
    Heading("Devices")
    val o = overview ?: return
    if (!o.enrolled) {
        Text("This device isn't enrolled, so it has no devices to show.")
        return
    }
    o.members.forEach { m ->
        Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    m.short + if (m.isThisDevice) "  (this device)" else "",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    "Added by ${m.admittedBy} on ${date(m.admittedAt)} · renews by ${date(m.expiresAt)}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (!m.isThisDevice) {
                OutlinedButton(onClick = { confirm = m }, enabled = !runner.busy) { Text("Remove") }
            }
        }
        HorizontalDivider()
    }
    confirm?.let { m ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("Remove ${m.short}?") },
            text = {
                Text(
                    "This device signs a removal. The device stops being a member, and the sites set up " +
                        "in Settings are told now; the rest learn at the next sign-in.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    runner.run({ engine.removeDevice(m.id) })
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel") } },
        )
    }
}

/**
 * An "Add a device" in progress. It lives above the screen switch, with the [Runner] whose
 * job it waits on, so leaving the screen and coming back finds the same pairing (and its
 * Cancel), never a fresh screen beside a wait that is still running.
 */
class PairingState {
    var invite by mutableStateOf<DesktopEngine.Invite?>(null)
    var code by mutableStateOf<String?>(null)
    var done by mutableStateOf<String?>(null)
}

@Composable
private fun AddDeviceScreen(engine: DesktopEngine, runner: Runner, pairing: PairingState) {
    var invite by pairing::invite
    var code by pairing::code
    var done by pairing::done
    Heading("Add a device")
    done?.let {
        Text(it)
        Spacer(Modifier.height(12.dp))
    }
    val inv = invite
    when {
        inv == null -> {
            Text(
                "Show a code for the new device to scan. You'll then compare a security code on both " +
                    "screens before this device signs anything.",
            )
            Spacer(Modifier.height(12.dp))
            Button(onClick = {
                done = null
                runner.run({ engine.startAddDevice() }) { i ->
                    invite = i
                    code = null
                    runner.run({ engine.awaitSecurityCode(i) }) { code = it }
                }
            }, enabled = !runner.busy) { Text("Show a code") }
        }

        code == null -> {
            Text("Scan this with the new device's authenticator app.")
            Spacer(Modifier.height(12.dp))
            QrCode(inv.qr)
            Spacer(Modifier.height(8.dp))
            SelectionContainer {
                Text(inv.qr, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
            Spacer(Modifier.height(12.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (runner.busy) CircularProgressIndicator(Modifier.width(20.dp).height(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("Waiting for the new device…")
            }
            TextButton(onClick = {
                runner.cancel()
                invite = null
            }) { Text(if (runner.busy) "Cancel" else "Start again") }
        }

        else -> {
            Text("Does the new device show this code?")
            Spacer(Modifier.height(12.dp))
            Text(code.orEmpty(), style = MaterialTheme.typography.displaySmall, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    runner.run({ engine.authorise(inv) }) {
                        invite = null
                        done = "Added. The new device is a member now."
                    }
                }, enabled = !runner.busy) { Text("It matches: add it") }
                OutlinedButton(onClick = {
                    runner.run({ engine.refuse(inv) }) {
                        invite = null
                        done = "Not added. The other device was told the codes didn't match."
                    }
                }, enabled = !runner.busy) { Text("It doesn't match") }
            }
        }
    }
}

@Composable
private fun SignInScreen(engine: DesktopEngine, runner: Runner, incoming: IncomingLink?) {
    var link by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<Pair<LoginApproval, LoginApproval.Request>?>(null) }
    var done by remember { mutableStateOf<String?>(null) }
    // A link opened with the app fills the field and clears what was shown; nothing is signed.
    LaunchedEffect(incoming) {
        if (incoming != null && incoming.value.startsWith(AppState.LOGIN_PREFIX)) {
            link = incoming.value
            pending = null
            done = null
        }
    }
    Heading("Approve a sign-in")
    Text("Paste the sign-in link a site shows (it starts with void-which-binds:login), or open one with this app.")
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(link, { link = it }, Modifier.fillMaxWidth(), label = { Text("Sign-in link") }, singleLine = true)
    Spacer(Modifier.height(8.dp))
    Button(onClick = {
        done = null
        pending = null // a failed lookup must not leave the previous sign-in approvable
        val asked = link
        // Shown only if the field still holds the link it was looked up for: a link opened
        // with the app meanwhile must never end up beside another login's Approve.
        runner.run({ engine.beginLogin(asked) }) { if (link == asked) pending = it }
    }, enabled = !runner.busy && link.isNotBlank()) { Text("Look it up") }
    done?.let {
        Spacer(Modifier.height(12.dp))
        Text(it)
    }
    val (approval, request) = pending ?: return
    Spacer(Modifier.height(16.dp))
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Field("Site", host(request.rp))
            Field("Signing in to", request.audience)
            Field("Expires", timestamp(request.expiresAt))
            Spacer(Modifier.height(12.dp))
            val finish = { chosen: Int? ->
                runner.run({ engine.approveLogin(approval, request, chosen) }) {
                    pending = null
                    done = "Signed in."
                }
            }
            if (request.isNumberMatch) {
                Text("Tap the number the site is showing.")
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    request.candidates.forEach { n ->
                        Button(onClick = { finish(n) }, enabled = !runner.busy) { Text(n.toString()) }
                    }
                }
            } else {
                Button(onClick = { finish(null) }, enabled = !runner.busy) { Text("Approve") }
            }
            TextButton(onClick = {
                pending = null
                done = "Not approved. Nothing was signed."
            }) { Text("Deny") }
        }
    }
}

@Composable
private fun ApprovalsScreen(engine: DesktopEngine, runner: Runner, incoming: IncomingLink?) {
    var link by remember { mutableStateOf("") }
    var fetched by remember { mutableStateOf<Pair<String, OpenedApproval>?>(null) }
    LaunchedEffect(incoming) {
        if (incoming != null && incoming.value.startsWith(AppState.APPROVE_PREFIX)) {
            link = incoming.value
            fetched = null
        }
    }
    Heading("Action approvals")
    Text("Paste an approval link (it starts with void-which-binds:approve), or open one with this app.")
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(link, {
        link = it
    }, Modifier.fillMaxWidth(), label = { Text("Approval link") }, singleLine = true)
    Spacer(Modifier.height(8.dp))
    Button(onClick = {
        fetched = null
        val asked = link
        runner.run({ engine.fetchApproval(asked) }) { if (link == asked) fetched = it }
    }, enabled = !runner.busy && link.isNotBlank()) { Text("Fetch") }
    val (broker, opened) = fetched ?: return
    Spacer(Modifier.height(16.dp))
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Field("Broker", host(broker))
            Field("Action", opened.action.kind)
            Field("Resource", opened.action.resource)
            Field("Summary", opened.action.summary)
            Field("Details", opened.action.params.decodeToString(), mono = true)
            Field("Expires", timestamp(opened.challenge.expiresAt))
            if (opened.challenge.candidates.isNotEmpty()) {
                Field("Numbers offered", opened.challenge.candidates.joinToString("  "))
            }
            Spacer(Modifier.height(12.dp))
            Text(
                "This desktop can show an approval but can't answer it yet: a broker takes answers " +
                    "through its host, and no endpoint for that is defined. Answer it on a phone.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun SettingsScreen(engine: DesktopEngine, runner: Runner) {
    val s = engine.settings
    var relay by remember { mutableStateOf(s.relay) }
    var rps by remember { mutableStateOf(s.membershipRps.joinToString("\n")) }
    var brokers by remember { mutableStateOf(s.brokers.joinToString("\n")) }
    var saved by remember { mutableStateOf(false) }
    fun lines(t: String) = t.lines().map(String::trim).filter(String::isNotEmpty)
    Heading("Settings")
    OutlinedTextField(relay, {
        relay = it
        saved = false
    }, Modifier.fillMaxWidth(), label = { Text("Pairing relay (for Add a device)") }, singleLine = true)
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(rps, {
        rps = it
        saved = false
    }, Modifier.fillMaxWidth(), label = { Text("Sites told of device changes (one URL a line)") }, minLines = 2)
    Spacer(Modifier.height(8.dp))
    OutlinedTextField(brokers, {
        brokers = it
        saved = false
    }, Modifier.fillMaxWidth(), label = { Text("Approval brokers (one URL a line)") }, minLines = 2)
    Spacer(Modifier.height(12.dp))
    Box {
        Button(onClick = {
            runner.run({ engine.saveSettings(DesktopSettings(relay.trim(), lines(rps), lines(brokers))) }) {
                saved = true
            }
        }, enabled = !runner.busy) { Text(if (saved) "Saved" else "Save") }
    }
}

private const val STATE_REFRESH_MILLIS = 15_000L
