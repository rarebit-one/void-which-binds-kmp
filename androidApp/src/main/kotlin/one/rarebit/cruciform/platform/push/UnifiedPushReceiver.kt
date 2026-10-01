package one.rarebit.cruciform.platform.push

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import one.rarebit.voidwhichbinds.PushPing
import one.rarebit.voidwhichbinds.VoidbindQr

/**
 * The Android **UnifiedPush** wake receiver — Void-Which-Binds's ONLY background push path
 * (self-hosted ntfy / UnifiedPush, no FCM/Google). A UnifiedPush distributor on the
 * phone (e.g. ntfy) broadcasts these intents when it registers an endpoint or
 * delivers a message; this receiver turns a delivered message into an app wake.
 *
 * It is deliberately implemented against the UnifiedPush **broadcast contract**
 * directly rather than pulling the connector library — the actions/extras below are
 * that contract, and keeping it dependency-free makes the app build without a
 * network-resolved dependency. The connector's `MessagingReceiver` can replace this
 * class verbatim later; the routing (below) is what matters.
 *
 * # The load-bearing invariant: the ping is opaque
 *
 * A delivered message body is the OPAQUE login tuple (`voidbind:login?rp=&id=`) and
 * nothing else — the exact same string a QR carries. This receiver does no crypto:
 * it hands the bytes to [PushPing] (which only decodes the tuple — there is no secret
 * in it to read) and, on a valid login, wakes [MainActivity] to surface the
 * number-match approval. The phone then pulls the real challenge from the RP over TLS
 * and signs it hardware-gated. A message that is not a voidbind login tuple is
 * silently dropped ([PushPing.parseOrNull]) — a stray push drives the app nowhere.
 */
class UnifiedPushReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            ACTION_MESSAGE -> onMessage(context, extractMessage(intent))

            ACTION_NEW_ENDPOINT -> intent.getStringExtra(EXTRA_ENDPOINT)?.let {
                PushEndpointStore(context).save(it)
            }

            ACTION_REGISTRATION_FAILED, ACTION_UNREGISTERED -> PushEndpointStore(context).clear()
        }
    }

    private fun onMessage(context: Context, body: ByteArray?) {
        val text = body?.decodeToString() ?: return
        // Opaque: only a login tuple wakes the app; anything else is dropped.
        val qr = PushPing.parseOrNull(text) as? VoidbindQr.Login ?: return
        // Surface via a full-screen-intent notification, NOT startActivity: a background
        // broadcast receiver's activity start is refused by Android's background-activity-
        // launch rules, and the ntfy distributor can only "raise" an app that owns a
        // foreground service (Cruciform does not at wake time). The notification launches
        // the approval directly on a locked/off screen and heads-up otherwise (issue #49).
        LoginWakeNotifier.notify(context, rebuildTuple(qr))
    }

    /** The opaque tuple to hand the app — rebuilt from the parsed parts (no secrets). */
    private fun rebuildTuple(login: VoidbindQr.Login): String =
        one.rarebit.voidwhichbinds.LoginQr.encode(login.request.rp, login.request.id)

    /**
     * UnifiedPush delivers the body under one of a few extra keys across versions.
     * UnifiedPush **v3** (what ntfy 1.25+ speaks — it advertises the `BYTES_MESSAGE`
     * feature) carries it as `bytesMessage`; the older keys are kept for v2 distributors.
     * Verified on-device 2026-09-04: ntfy's MESSAGE arrived with `extras=[bytesMessage, token]`.
     */
    private fun extractMessage(intent: Intent): ByteArray? = intent.getByteArrayExtra(EXTRA_BYTES_MESSAGE)
        ?: intent.getByteArrayExtra(EXTRA_BYTES)
        ?: intent.getByteArrayExtra(EXTRA_MESSAGE_BYTES)
        ?: intent.getStringExtra(EXTRA_MESSAGE_STRING)?.encodeToByteArray()

    companion object {
        // The UnifiedPush broadcast contract (org.unifiedpush.android.connector.*).
        const val ACTION_MESSAGE = "org.unifiedpush.android.connector.MESSAGE"
        const val ACTION_NEW_ENDPOINT = "org.unifiedpush.android.connector.NEW_ENDPOINT"
        const val ACTION_REGISTRATION_FAILED = "org.unifiedpush.android.connector.REGISTRATION_FAILED"
        const val ACTION_UNREGISTERED = "org.unifiedpush.android.connector.UNREGISTERED"

        const val EXTRA_ENDPOINT = "endpoint"
        private const val EXTRA_BYTES_MESSAGE = "bytesMessage" // UnifiedPush v3 (ntfy 1.25+)
        private const val EXTRA_BYTES = "bytes"
        private const val EXTRA_MESSAGE_BYTES = "message"
        private const val EXTRA_MESSAGE_STRING = "messageString"

        /** Intent extra carrying the opaque login tuple from a push into [MainActivity]. */
        const val EXTRA_LOGIN_TUPLE = "one.rarebit.voidbind.LOGIN_TUPLE"
    }
}
