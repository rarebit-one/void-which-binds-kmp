package one.rarebit.cruciform.platform.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import one.rarebit.cruciform.MainActivity

/** A user-tapped notification is the only background entry point for an unwrap wake. */
object OffloadWakeNotifier {
    private const val CHANNEL = "offload-wake"
    private const val NOTIFICATION_ID = 0x0F_F10AD

    fun notify(context: Context, wake: String) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "Space unlock requests", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "A paired Heyarr desktop is asking to unlock an encrypted space."
                    setShowBadge(true)
                },
            )
        }
        val open = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(UnifiedPushReceiver.EXTRA_OFFLOAD_WAKE, wake)
        }
        val pending = PendingIntent.getActivity(
            context,
            NOTIFICATION_ID,
            open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Unlock an encrypted space?")
            .setContentText("A paired Heyarr desktop is waiting for your approval.")
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pending)
            .setFullScreenIntent(pending, true)
            .build()
        val notifications = NotificationManagerCompat.from(context)
        if (notifications.areNotificationsEnabled()) {
            runCatching { notifications.notify(NOTIFICATION_ID, notification) }
        }
    }
}
