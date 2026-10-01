package one.rarebit.cruciform.ui.components

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.layout.ContentScale
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * Renders [content] as a QR code — the invite this device shows when it is the
 * existing (initiator) side of a pairing. Encoded on a white field for reliable
 * scanning; the payload is a `void-which-binds:pair?…` URI produced by the library.
 */
@Composable
fun QrImage(content: String, modifier: Modifier = Modifier, sizePx: Int = 512) {
    val bitmap = remember(content, sizePx) { encodeQr(content, sizePx) }
    Image(
        bitmap = bitmap.asImageBitmap(),
        contentDescription = "QR code",
        modifier = modifier,
        contentScale = ContentScale.Fit,
    )
}

private fun encodeQr(content: String, size: Int): Bitmap {
    val hints = mapOf(
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        EncodeHintType.MARGIN to 1,
    )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints)
    val dark = android.graphics.Color.BLACK
    val light = VbColors.TextPrimary.toArgb()
    val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    for (x in 0 until size) {
        for (y in 0 until size) {
            bmp.setPixel(x, y, if (matrix[x, y]) dark else light)
        }
    }
    return bmp
}
