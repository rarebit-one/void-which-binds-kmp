package one.rarebit.cruciform.platform

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder
import one.rarebit.cruciform.domain.RecoveryBackup
import kotlin.math.max

/**
 * The printable recovery sheet, laid out as pure geometry: which strings and boxes go
 * where on the page, in PDF points (1/72 inch, origin top-left). No Android types, so
 * the layout is unit-tested on the JVM; [RecoverySheetPrinter] draws the result onto a
 * `PdfDocument` page and hands it to the print framework.
 *
 * A port of void-which-binds-go `recovery/sheet` (its HTML page, sized in millimetres): the
 * secret as an UPPER-CASE QR code (QR alphanumeric mode, so version 4 at medium error
 * correction), the secret in four-character groups, the user fingerprint and user ID,
 * numbered instructions, corner cut marks and a 50 mm calibration bar. If the bar does
 * not measure 50 mm the page was scaled and the QR code may not scan, so the sheet says
 * to reprint at 100%.
 *
 * The sizes are the Go stylesheet's: an A4 page with 12 mm margins, a 170 mm card
 * (Letter-safe) with 10 × 12 mm padding, a 58 mm QR code (quiet zone included) pulled
 * 5 mm up and left so the code itself lines up with the text, then an 8 mm gap to the
 * grouped secret.
 */
internal object RecoverySheet {
    /** ISO A4 in points (210 × 297 mm), rounded as `PdfDocument` takes whole points. */
    const val A4_WIDTH_PT = 595
    const val A4_HEIGHT_PT = 842

    const val PT_PER_MM = 72f / 25.4f

    /** Characters per written group, as the apps display the secret. */
    const val GROUP_SIZE = 4
    const val GROUPS_PER_ROW = 4

    const val PAGE_MARGIN_MM = 12f
    const val CARD_WIDTH_MM = 170f
    const val CARD_PAD_X_MM = 12f
    const val CARD_PAD_Y_MM = 10f
    const val QR_MM = 58f
    const val QR_PULL_MM = 5f
    const val QR_GAP_MM = 8f
    const val CUT_MM = 6f
    const val CUT_STROKE_MM = 0.3f
    const val RULER_MM = 50f
    const val RULER_HEIGHT_MM = 6f
    const val RULER_BAR_MM = 1.2f
    const val RULER_TICK_MM = 5f
    const val RULER_TICK_WIDTH_MM = 0.25f
    const val RULER_TICK_STEP_MM = 10f

    // The Go stylesheet's vertical rhythm, in millimetres.
    private const val HEADING_GAP_MM = 1f
    private const val META_GAP_MM = 6f
    private const val FINGERPRINT_GAP_MM = 4f
    private const val NOTES_GAP_MM = 6f
    private const val NOTE_INDENT_MM = 5f
    private const val NOTE_GAP_MM = 1.5f
    private const val RULER_GAP_MM = 8f
    private const val RULER_TEXT_GAP_MM = 1f

    /** The standard four-module quiet zone scanners need, as in go-qrcode's bitmap. */
    const val QUIET_ZONE_MODULES = 4

    const val HEADING = "Recovery secret"
    const val CALIBRATION =
        "This bar must measure exactly 50 mm. If it doesn't, the page was scaled: reprint at 100% (actual size)."

    fun mm(value: Float): Float = value * PT_PER_MM

    /** What one printed page carries (void-which-binds-go `sheet.Sheet`, `ForSecret`). */
    data class Content(
        val heading: String,
        /** What the QR code carries: the secret in UPPER case. */
        val payload: String,
        val groups: List<String>,
        val fingerprint: String,
        val userId: String,
        /** e.g. "25 September 2026". */
        val dateLabel: String,
        val notes: List<String>,
    ) {
        override fun toString(): String = "Content(<redacted>, fingerprint=$fingerprint)"
    }

    /** The sheet for [backup], dated [dateLabel]. Mirrors `sheet.ForSecret`. */
    fun forBackup(backup: RecoveryBackup, dateLabel: String): Content {
        val encoded = backup.rawSecret
        val fp = backup.fingerprint
        return Content(
            heading = HEADING,
            payload = encoded.uppercase(),
            groups = group(encoded),
            fingerprint = fp,
            userId = backup.userId,
            dateLabel = dateLabel,
            notes = listOf(
                "This secret IS your identity. Anyone who holds it can become you, so keep it offline: " +
                    "no photos, no cloud, no email.",
                "Check it now and once a year, without using it: Cruciform → Settings → Test recovery secret, " +
                    "or 'void-which-binds recovery verify --secret-file -'. The fingerprint shown must read $fp.",
                "To restore after losing every device: Cruciform → Restore (scan the code, or type the groups " +
                    "above, spaces allowed), or 'void-which-binds identity recover --secret-file -'.",
                "Case does not matter and a single wrong character is refused, never mistaken for another identity.",
            ),
        )
    }

    /** Split [text] into the groups a person copies: four characters each. */
    fun group(text: String): List<String> = text.chunked(GROUP_SIZE)

    /** A QR symbol's modules, quiet zone included: `size × size`, dark = true. */
    class QrModules(val size: Int, val version: Int, private val dark: BooleanArray) {
        operator fun get(x: Int, y: Int): Boolean = dark[y * size + x]
    }

    /**
     * Encode [payload] at medium error correction (as `QrImage` does). ZXing picks the
     * alphanumeric mode for an upper-case secret, which keeps it to version 4.
     */
    fun encodeQr(payload: String): QrModules {
        val code = Encoder.encode(payload, ErrorCorrectionLevel.M)
        val matrix = code.matrix
        val size = matrix.width + 2 * QUIET_ZONE_MODULES
        val dark = BooleanArray(size * size)
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                val index = (y + QUIET_ZONE_MODULES) * size + x + QUIET_ZONE_MODULES
                dark[index] = matrix.get(x, y).toInt() == 1
            }
        }
        return QrModules(size, code.version.versionNumber, dark)
    }

    enum class Font { SERIF, SERIF_BOLD, MONO, MONO_BOLD }

    /** A text style: [font], [sizePt], and CSS-style letter spacing in em. */
    data class TextStyle(val font: Font, val sizePt: Float, val letterSpacingEm: Float = 0f)

    /** The Go stylesheet's text styles (Georgia → serif, DejaVu Sans Mono → monospace). */
    object Styles {
        private const val HEADING_PT = 20f
        private const val HEADING_SPACING_EM = 0.02f
        private const val SMALL_PT = 9f
        private const val SECRET_PT = 13f
        private const val SECRET_SPACING_EM = 0.08f
        private const val FINGERPRINT_PT = 12f
        private const val FINGERPRINT_SPACING_EM = 0.1f
        private const val USER_ID_PT = 7f
        private const val NOTE_PT = 9.5f
        private const val RULER_PT = 8f

        val Heading = TextStyle(Font.SERIF_BOLD, HEADING_PT, HEADING_SPACING_EM)
        val Meta = TextStyle(Font.SERIF, SMALL_PT)
        val Secret = TextStyle(Font.MONO, SECRET_PT, SECRET_SPACING_EM)
        val FingerprintLabel = TextStyle(Font.SERIF, SMALL_PT)
        val Fingerprint = TextStyle(Font.MONO_BOLD, FINGERPRINT_PT, FINGERPRINT_SPACING_EM)
        val UserId = TextStyle(Font.MONO, USER_ID_PT)
        val Note = TextStyle(Font.SERIF, NOTE_PT)
        val Ruler = TextStyle(Font.SERIF, RULER_PT)
    }

    /** One drawing operation, in points. */
    sealed interface Op {
        /** [text] drawn left-aligned from [x] on the [baseline]. */
        data class Text(val text: String, val x: Float, val baseline: Float, val style: TextStyle) : Op

        /** A filled black rectangle. */
        data class Box(val x: Float, val y: Float, val width: Float, val height: Float) : Op

        /** The QR symbol drawn into the [size]-point square at ([x], [y]). */
        data class Qr(val x: Float, val y: Float, val size: Float) : Op
    }

    /** The laid-out page: its size, the ops in drawing order, and where the card sits. */
    data class Page(
        val width: Float,
        val height: Float,
        val ops: List<Op>,
        val cardLeft: Float,
        val cardTop: Float,
        val cardRight: Float,
        val cardBottom: Float,
    )

    /** Width of a string in points, as the renderer's font will draw it. */
    fun interface Measure {
        fun width(text: String, style: TextStyle): Float
    }

    /**
     * Lay [content] out on a [pageWidth] × [pageHeight]-point page (A4 by default; a
     * Letter page gets the same card, centred). [measure] is the renderer's font metric,
     * used only to wrap text and space the groups.
     */
    fun layout(
        content: Content,
        measure: Measure,
        pageWidth: Float = A4_WIDTH_PT.toFloat(),
        pageHeight: Float = A4_HEIGHT_PT.toFloat(),
    ): Page = Layout(content, measure, pageWidth).run {
        build()
        Page(pageWidth, pageHeight, ops, cardLeft, cardTop, cardLeft + mm(CARD_WIDTH_MM), cardBottom)
    }

    private const val LINE_HEIGHT = 1.45f
    private const val SECRET_LINE_HEIGHT = 1.9f

    /** Where the baseline of a [style] line sits in a line box of [lineHeight] starting at [top]. */
    private fun baseline(top: Float, style: TextStyle, lineHeight: Float = LINE_HEIGHT): Float {
        val box = style.sizePt * lineHeight
        return top + (box - style.sizePt) / 2f + style.sizePt * ASCENT
    }

    private const val ASCENT = 0.8f

    /** The mutable walk down the card; one instance per [layout] call. */
    private class Layout(val content: Content, val measure: Measure, pageWidth: Float) {
        val ops = mutableListOf<Op>()
        val cardLeft = (pageWidth - mm(CARD_WIDTH_MM)) / 2f
        val cardTop = mm(PAGE_MARGIN_MM)
        var cardBottom = 0f
        val left = cardLeft + mm(CARD_PAD_X_MM)
        val width = mm(CARD_WIDTH_MM - 2 * CARD_PAD_X_MM)
        var y = cardTop + mm(CARD_PAD_Y_MM)

        fun build() {
            header()
            main()
            notes()
            ruler()
            cardBottom = y + mm(CARD_PAD_Y_MM)
            cutMarks()
        }

        private fun line(text: String, x: Float, style: TextStyle, lineHeight: Float = LINE_HEIGHT) {
            ops += Op.Text(text, x, baseline(y, style, lineHeight), style)
            y += style.sizePt * lineHeight
        }

        private fun header() {
            line(content.heading, left, Styles.Heading)
            y += mm(HEADING_GAP_MM)
            line("Void-Which-Binds identity · written ${content.dateLabel}", left, Styles.Meta)
            y += mm(META_GAP_MM)
        }

        /** The QR code on the left; the groups, fingerprint and user ID beside it. */
        private fun main() {
            val top = y
            val qrLeft = left - mm(QR_PULL_MM)
            ops += Op.Qr(qrLeft, top - mm(QR_PULL_MM), mm(QR_MM))
            val colLeft = qrLeft + mm(QR_MM) + mm(QR_GAP_MM)
            val colWidth = left + width - colLeft

            val ch = measure.width("0", Styles.Secret)
            val widest = content.groups.maxOf { measure.width(it, Styles.Secret) }
            val cell = max(widest, GROUP_SIZE * ch) + SPACE_CH * ch
            for (row in content.groups.chunked(GROUPS_PER_ROW)) {
                val base = baseline(y, Styles.Secret, SECRET_LINE_HEIGHT)
                row.forEachIndexed { i, g -> ops += Op.Text(g, colLeft + i * cell, base, Styles.Secret) }
                y += Styles.Secret.sizePt * SECRET_LINE_HEIGHT
            }

            y += mm(FINGERPRINT_GAP_MM)
            val label = "Fingerprint "
            val fpBase = baseline(y, Styles.Fingerprint)
            val fpLeft = colLeft + measure.width(label, Styles.FingerprintLabel)
            ops += Op.Text(label, colLeft, fpBase, Styles.FingerprintLabel)
            ops += Op.Text(content.fingerprint, fpLeft, fpBase, Styles.Fingerprint)
            y += Styles.Fingerprint.sizePt * LINE_HEIGHT

            // `word-break: break-all`: a 72-character key wraps anywhere.
            for (part in wrapChars(content.userId, colWidth, Styles.UserId)) line(part, colLeft, Styles.UserId)

            y = max(y, top - mm(QR_PULL_MM) + mm(QR_MM))
        }

        private fun notes() {
            y += mm(NOTES_GAP_MM)
            val indent = mm(NOTE_INDENT_MM)
            content.notes.forEachIndexed { i, note ->
                if (i > 0) y += mm(NOTE_GAP_MM)
                val marker = "${i + 1}. "
                val first = baseline(y, Styles.Note)
                ops += Op.Text(marker, left + indent - measure.width(marker, Styles.Note), first, Styles.Note)
                for (part in wrapWords(note, width - indent, Styles.Note)) line(part, left + indent, Styles.Note)
            }
        }

        private fun ruler() {
            y += mm(RULER_GAP_MM)
            for (part in wrapWords(CALIBRATION, width, Styles.Ruler)) line(part, left, Styles.Ruler)
            y += mm(RULER_TEXT_GAP_MM)
            ops += Op.Box(left, y, mm(RULER_MM), mm(RULER_BAR_MM))
            // Ticks every 10 mm from 0 to 40, and one flush with the bar's right end.
            var tick = 0f
            while (tick < RULER_MM) {
                ops += Op.Box(left + mm(tick), y, mm(RULER_TICK_WIDTH_MM), mm(RULER_TICK_MM))
                tick += RULER_TICK_STEP_MM
            }
            ops += Op.Box(left + mm(RULER_MM - RULER_TICK_WIDTH_MM), y, mm(RULER_TICK_WIDTH_MM), mm(RULER_TICK_MM))
            y += mm(RULER_HEIGHT_MM)
        }

        /** L-shaped marks, 6 mm long, at the card's four corners. */
        private fun cutMarks() {
            val len = mm(CUT_MM)
            val stroke = mm(CUT_STROKE_MM)
            val right = cardLeft + mm(CARD_WIDTH_MM)
            val corners = listOf(cardLeft to cardTop, right to cardTop, cardLeft to cardBottom, right to cardBottom)
            for ((cx, cy) in corners) {
                val hx = if (cx == cardLeft) cx else cx - len
                val vx = if (cx == cardLeft) cx else cx - stroke
                val hy = if (cy == cardTop) cy else cy - stroke
                val vy = if (cy == cardTop) cy else cy - len
                ops += Op.Box(hx, hy, len, stroke)
                ops += Op.Box(vx, vy, stroke, len)
            }
        }

        /** Greedy word wrap into [limit]-point lines; an over-long word is split by characters. */
        fun wrapWords(text: String, limit: Float, style: TextStyle): List<String> {
            val lines = mutableListOf<String>()
            var current = ""
            for (word in text.split(' ').filter { it.isNotEmpty() }) {
                val candidate = if (current.isEmpty()) word else "$current $word"
                if (measure.width(candidate, style) <= limit) {
                    current = candidate
                } else {
                    if (current.isNotEmpty()) lines += current
                    val parts = wrapChars(word, limit, style)
                    lines += parts.dropLast(1)
                    current = parts.last()
                }
            }
            if (current.isNotEmpty()) lines += current
            return lines
        }

        /** Break [text] anywhere so each line fits [limit] points (at least one character a line). */
        fun wrapChars(text: String, limit: Float, style: TextStyle): List<String> {
            val lines = mutableListOf<String>()
            var start = 0
            while (start < text.length) {
                var end = start + 1
                while (end < text.length && measure.width(text.substring(start, end + 1), style) <= limit) end++
                lines += text.substring(start, end)
                start = end
            }
            return lines
        }
    }

    /** `margin-right: 1.4ch` after each group. */
    private const val SPACE_CH = 1.4f
}
