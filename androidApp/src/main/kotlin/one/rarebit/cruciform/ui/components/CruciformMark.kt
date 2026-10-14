package one.rarebit.cruciform.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import one.rarebit.cruciform.ui.theme.VbColors

/**
 * The Cruciform mark: the knot from the launcher icon. One mint band runs corner to corner
 * around an empty square (the void), throwing a crossed loop out on each side; the fern
 * square marks the void. Drawn rather than shipped as a raster so it stays crisp at any
 * size and re-tints with the theme.
 *
 * The path data is the launcher foreground's (`res/drawable/ic_launcher_foreground.xml`),
 * on its 108-unit canvas; only the motif's 66-unit square is drawn here, so the mark fills
 * [size] instead of carrying the adaptive icon's margin.
 */
@Composable
fun CruciformMark(size: Dp = 32.dp, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier.size(size)) {
        val k = this.size.minDimension / MOTIF
        scale(k, pivot = Offset.Zero) {
            translate(-MOTIF_ORIGIN, -MOTIF_ORIGIN) {
                drawPath(knot, VbColors.Mint, style = Stroke(width = BAND, join = StrokeJoin.Round))
                drawPath(void, VbColors.Fern, style = Stroke(width = FRAME))
            }
        }
    }
}

/** The motif's square on the 108-unit icon canvas: centre 54, loop tips at radius 33. */
private const val MOTIF = 66f
private const val MOTIF_ORIGIN = 54f - MOTIF / 2f
private const val BAND = 5f
private const val FRAME = 1.6f

private val knot = PathParser().parsePathString(
    "M44.45,51.43 L48,48 L59.39,36.21 A7.5,7.5 0 1,0 48.61,36.21 L51.43,39.13 " +
        "M56.57,44.45 L60,48 L71.79,59.39 A7.5,7.5 0 1,0 71.79,48.61 L68.87,51.43 " +
        "M63.55,56.57 L60,60 L48.61,71.79 A7.5,7.5 0 1,0 59.39,71.79 L56.57,68.87 " +
        "M51.43,63.55 L48,60 L36.21,48.61 A7.5,7.5 0 1,0 36.21,59.39 L39.13,56.57",
).toPath()

private val void = PathParser().parsePathString("M51,51 H57 V57 H51 Z").toPath()
