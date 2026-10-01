package one.rarebit.cruciform

import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.viewmodel.compose.viewModel
import one.rarebit.cruciform.domain.DeviceVoidbindEngine
import one.rarebit.cruciform.domain.PreviewVoidbindEngine
import one.rarebit.cruciform.domain.VoidbindEngine
import one.rarebit.cruciform.handoff.Handoff
import one.rarebit.cruciform.handoff.HandoffRouter
import one.rarebit.cruciform.handoff.RpAppIdentity
import one.rarebit.cruciform.handoff.SamePhoneJoin
import one.rarebit.cruciform.handoff.SamePhonePairCallback
import one.rarebit.cruciform.pairing.ServiceKeepAlive
import one.rarebit.cruciform.platform.AndroidBiometricAuthenticator
import one.rarebit.cruciform.platform.ApprovalPolicyStore
import one.rarebit.cruciform.platform.IdentityStore
import one.rarebit.cruciform.platform.NotifySettings
import one.rarebit.cruciform.platform.OkHttpTransport
import one.rarebit.cruciform.platform.RelaySettings
import one.rarebit.cruciform.platform.push.PushEndpointStore
import one.rarebit.cruciform.platform.push.UnifiedPushReceiver
import one.rarebit.cruciform.platform.push.UnifiedPushRegistrar
import one.rarebit.cruciform.ui.nav.CruciformNavHost
import one.rarebit.cruciform.ui.theme.CruciformTheme

/**
 * A [FragmentActivity] because `BiometricPrompt` binds to one. Chooses the engine:
 * the real [DeviceVoidbindEngine] (hardware key + coordinators over the network,
 * biometric-gated) or the [PreviewVoidbindEngine] (in-memory mockup data). The
 * preview engine is the default so the UI is reviewable without hardware; the real
 * one is selected at BUILD time with `./gradlew -PdeviceEngine=true …`
 * ([BuildConfig.USE_DEVICE_ENGINE]) — no source edit.
 *
 * Two ways the activity is woken into a login from outside its own UI, both hoisted
 * into one [handoff] the nav graph consumes (updated on [onNewIntent] too):
 *
 * - a **push wake** ([UnifiedPushReceiver]) with the opaque tuple in
 *   [UnifiedPushReceiver.EXTRA_LOGIN_TUPLE] — the app stays open afterwards;
 * - a **same-device deep link** (`ACTION_VIEW void-which-binds:login?…` / `void-which-binds:pair?…`)
 *   from a relying-party app on this phone — the identical approval flow, and then
 *   [finishHandoff] returns to the caller (finishing this activity, and launching the
 *   RP's optional private-scheme `callback` bare after a successful approval). The
 *   activity is `singleTask` so a warm app receives the link via [onNewIntent].
 */
class MainActivity : FragmentActivity() {

    private var handoff by mutableStateOf<Handoff?>(null)
    private var handoffSeq = 0

    /**
     * A `cruciform://pair-joined` report from a relying-party app on THIS phone
     * (ADR-0008), with whatever the system could tell us about who sent it. The nav
     * graph hands it to the invite coordinator, which checks it against the relay.
     */
    private var samePhoneJoin by mutableStateOf<SamePhoneJoin?>(null)
    private var samePhoneSeq = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A cold start from a deep link / push: route the launching intent. On a
        // recreation (rotation) the intent is the same one, but the handoff state is
        // fresh — re-routing it re-fires the approval, which is the right thing (the
        // flow state it held was ephemeral).
        handoff = routeIntent(intent)
        samePhoneJoin = routeSamePhone(intent)
        setContent {
            CruciformTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    val engine: VoidbindEngine = remember {
                        if (BuildConfig.USE_DEVICE_ENGINE) {
                            DeviceVoidbindEngine(
                                store = IdentityStore(applicationContext),
                                policyStore = ApprovalPolicyStore(applicationContext),
                                transport = OkHttpTransport(),
                                biometric = AndroidBiometricAuthenticator(this@MainActivity),
                                // Read at invite time, not captured here: Settings → "Pairing
                                // relay" applies to the next "Add a device" without a restart.
                                relay = RelaySettings(applicationContext)::current,
                                // Same discipline for the push plane: read at
                                // registration time, so Settings -> "Push plane"
                                // applies on the next app open without a restart.
                                notify = NotifySettings(applicationContext)::current,
                            )
                        } else {
                            PreviewVoidbindEngine()
                        }
                    }
                    // The wake surfaces as a notification (LoginWakeNotifier), so on
                    // Android 13+ ask for POST_NOTIFICATIONS once — without it the wake is
                    // silently dropped. Best-effort: a denial just means no background wake,
                    // and scanned-QR login still works.
                    val notifPermission = rememberLauncherForActivityResult(
                        ActivityResultContracts.RequestPermission(),
                    ) { /* granted-or-not: the notifier guards on areNotificationsEnabled() */ }
                    LaunchedEffect(Unit) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                            ContextCompat.checkSelfPermission(
                                this@MainActivity,
                                android.Manifest.permission.POST_NOTIFICATIONS,
                            ) != PackageManager.PERMISSION_GRANTED
                        ) {
                            notifPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                        }
                    }
                    // On open, ASK a UnifiedPush distributor (e.g. ntfy) for a wake
                    // endpoint. Without this the distributor is never contacted and no
                    // endpoint is ever minted — the receiver has nothing to receive.
                    // Idempotent (a stable token → the same endpoint), best-effort: no
                    // distributor just means no background wake and scanned-QR login still
                    // works.
                    LaunchedEffect(Unit) {
                        UnifiedPushRegistrar.register(applicationContext)
                    }
                    // Register the wake endpoint with the notify plane, cert-authenticated,
                    // as soon as one exists — the current value on open, and again the
                    // instant a fresh NEW_ENDPOINT lands (the receiver writes the same prefs).
                    LaunchedEffect(engine) {
                        PushEndpointStore(applicationContext).flow().collect { endpoint ->
                            endpoint?.let { engine.registerForPush(it) }
                        }
                    }
                    // The invite coordinator (ADR-0007) lives in the ViewModel scope with a
                    // foreground-service keep-alive, so a minted invite keeps waiting on the
                    // relay while the user is in the relying-party app on this phone.
                    val vm: AppViewModel = viewModel {
                        AppViewModel(
                            engine,
                            relayUrl = RelaySettings(applicationContext)::current,
                            keepAlive = ServiceKeepAlive(applicationContext),
                        )
                    }
                    CruciformNavHost(
                        vm,
                        handoff = handoff,
                        onHandoffFinished = ::finishHandoff,
                        samePhoneJoin = samePhoneJoin,
                        onSamePhoneDone = ::finishSamePhone,
                        onSamePhoneRefused = ::refuseSamePhone,
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        // A warm app woken by a fresh push or a fresh deep link: surface the new login.
        routeIntent(intent)?.let { handoff = it }
        routeSamePhone(intent)?.let { samePhoneJoin = it }
    }

    /**
     * The one-tap report, if this intent is one. The caller is identified from
     * `referrer` — the system's attribution, not anything the URI claims — and only to
     * label the sheet and address the return trip; the security decision is the
     * comparison against the relay, made in the coordinator.
     */
    private fun routeSamePhone(intent: Intent?): SamePhoneJoin? {
        intent ?: return null
        return when (val r = SamePhonePairCallback.route(intent.action, intent.dataString)) {
            is SamePhonePairCallback.Joined -> {
                val caller = referrer?.takeIf { it.scheme == "android-app" }?.host
                SamePhoneJoin(r, RpAppIdentity.resolve(this, caller), ++samePhoneSeq)
            }

            is SamePhonePairCallback.Malformed -> {
                Log.w(TAG, "same-phone callback ignored: ${r.message}")
                null
            }

            null -> null
        }
    }

    /**
     * The add is signed and delivered on the one-tap path: send the human back to the
     * relying-party app's own `<scheme>://pair-done?session=` landing so they end up
     * where they started, enrolled, and finish so this task does not sit on top of it.
     * A scheme we cannot address (or an RP that no longer handles it) just means the
     * user comes back through recent apps — the enrolment is done either way.
     */
    private fun finishSamePhone(scheme: String?, session: String) {
        RpAppIdentity.openDone(this, scheme, session)
        samePhoneJoin = null
        finishAndRemoveTask()
    }

    /**
     * The one-tap report was refused: hand the verdict to the RP's landing so it stops
     * waiting, but stay — this task's failure dialog is the human's explanation, and
     * they come back to it through recent apps.
     */
    private fun refuseSamePhone(scheme: String?, session: String, reason: String) {
        RpAppIdentity.openDone(this, scheme, session, refusedFor = reason)
        samePhoneJoin = null
    }

    /**
     * The push extra wins if present (the receiver built it from a parsed ping); else a
     * `void-which-binds:` VIEW deep link. The URI is untrusted input from another app — the
     * router parses it as strictly as a scan and drops a malformed callback.
     */
    private fun routeIntent(intent: Intent?): Handoff? {
        intent ?: return null
        val seq = ++handoffSeq
        return HandoffRouter.fromPush(intent.getStringExtra(UnifiedPushReceiver.EXTRA_LOGIN_TUPLE), seq)
            ?: HandoffRouter.fromDeepLink(intent.action, intent.dataString, seq)
    }

    /**
     * The human decided (or the login could not be shown). For a deep-link handoff:
     * launch the RP's callback — bare, nothing appended — only after a SUCCESSFUL
     * approval, then finish so the caller's task resumes (it learns the outcome from
     * its own broker poll, never from us). A push wake stays in the app.
     */
    private fun finishHandoff(done: Handoff, approved: Boolean) {
        if (handoff?.seq == done.seq) handoff = null
        if (!done.returnsToCaller) return
        val callback = done.callback
        if (approved && callback != null) {
            try {
                startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse(callback))
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            } catch (e: ActivityNotFoundException) {
                Log.w(TAG, "callback has no handler; caller will resume by itself")
            } catch (e: SecurityException) {
                Log.w(TAG, "callback refused by the system; caller will resume by itself")
            }
        }
        finishAndRemoveTask()
    }

    private companion object {
        const val TAG = "CruciformHandoff"
    }
}
