package one.rarebit.cruciform.desktop.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** [text] as a QR code, black on white with a quiet zone, for a phone to scan off the screen. */
@Composable
fun QrCode(text: String, size: Dp = 280.dp) {
    val matrix = remember(text) {
        QRCodeWriter().encode(
            text,
            BarcodeFormat.QR_CODE,
            0,
            0,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to QUIET_ZONE_CELLS),
        )
    }
    Canvas(Modifier.size(size)) {
        drawRect(Color.White)
        val cell = this.size.width / matrix.width
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix.get(x, y)) {
                    drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + SEAM_OVERLAP, cell + SEAM_OVERLAP))
                }
            }
        }
    }
}

/** The QR spec's quiet zone, in cells. */
private const val QUIET_ZONE_CELLS = 4

/** Each cell overdraws by half a pixel, so no hairline seams show between dark cells. */
private const val SEAM_OVERLAP = 0.5f
