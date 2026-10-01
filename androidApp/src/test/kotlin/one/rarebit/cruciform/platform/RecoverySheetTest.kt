package one.rarebit.cruciform.platform

import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.decoder.Mode
import com.google.zxing.qrcode.encoder.Encoder
import one.rarebit.cruciform.domain.RecoveryBackup
import one.rarebit.cruciform.platform.RecoverySheet.Op
import one.rarebit.cruciform.platform.RecoverySheet.mm
import one.rarebit.voidwhichbinds.RecoverySecret
import one.rarebit.voidwhichbinds.UserIdentity
import org.junit.Test
import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The recovery sheet's content and geometry (void-which-binds-go `recovery/sheet` parity). The
 * PDF drawing and the print dialog need a device (docs/DEVICE-TESTING.md, Test 2d);
 * everything they are handed is decided here.
 */
class RecoverySheetTest {
    private val user = UserIdentity.create()
    private val raw = user.recovery.format()
    private val backup = RecoveryBackup(
        groupedSecret = raw.chunked(4).joinToString(" "),
        rawSecret = raw,
        fingerprint = user.fingerprint,
        userId = user.userId.render(),
    )
    private val content = RecoverySheet.forBackup(backup, "25 September 2026")

    /**
     * A deterministic stand-in for font metrics: 0.6 em a character plus letter spacing.
     * Monospace-wide for the serif text too, so wrapping here is conservative.
     */
    private val measure = RecoverySheet.Measure { text, style ->
        text.length * style.sizePt * (0.6f + style.letterSpacingEm)
    }

    private fun near(expected: Float, actual: Float) {
        assertTrue(abs(expected - actual) < 0.01f, "expected $expected, got $actual")
    }

    private fun RecoverySheet.Page.texts() = ops.filterIsInstance<Op.Text>()

    private fun RecoverySheet.Page.boxes() = ops.filterIsInstance<Op.Box>()

    @Test
    fun `millimetres are converted at 72 points to the inch`() {
        near(72f, mm(25.4f))
        near(mm(210f), RecoverySheet.A4_WIDTH_PT.toFloat() + 0.28f)
    }

    @Test
    fun `the content mirrors the Go sheet's ForSecret`() {
        assertEquals("Recovery secret", content.heading)
        assertEquals(raw.uppercase(), content.payload)
        assertEquals(user.recovery, RecoverySecret.parse(content.payload))
        assertEquals(raw.chunked(4), content.groups)
        assertTrue(content.groups.all { it.length <= 4 })
        assertEquals(user.fingerprint, content.fingerprint)
        assertEquals(user.userId.render(), content.userId)
        assertEquals(4, content.notes.size)
        assertTrue(content.notes[1].endsWith("must read ${user.fingerprint}."))
        assertFalse(content.toString().contains(raw), "the secret must not reach a log")
        assertFalse(content.toString().contains(raw.uppercase()))
    }

    @Test
    fun `the QR code is the upper-case secret, alphanumeric, version 4 at medium correction`() {
        val code = Encoder.encode(content.payload, ErrorCorrectionLevel.M)
        assertEquals(Mode.ALPHANUMERIC, code.mode)
        assertEquals(4, code.version.versionNumber)

        val qr = RecoverySheet.encodeQr(content.payload)
        assertEquals(4, qr.version)
        assertEquals(33 + 2 * RecoverySheet.QUIET_ZONE_MODULES, qr.size)
        // The quiet zone is light all round; the top-left finder starts right inside it.
        val zone = RecoverySheet.QUIET_ZONE_MODULES
        for (i in 0 until qr.size) {
            for (j in 0 until zone) {
                assertFalse(qr[i, j] || qr[j, i] || qr[i, qr.size - 1 - j] || qr[qr.size - 1 - j, i])
            }
        }
        assertTrue(qr[zone, zone])

        // Why upper case: the lower-case form needs byte mode and a bigger symbol.
        assertTrue(RecoverySheet.encodeQr(raw).version > 4)
    }

    @Test
    fun `the A4 page carries the Go sheet's millimetre geometry`() {
        val page = RecoverySheet.layout(content, measure)

        assertEquals(595f, page.width)
        assertEquals(842f, page.height)
        near(mm(170f), page.cardRight - page.cardLeft)
        near((595f - mm(170f)) / 2f, page.cardLeft)
        near(mm(12f), page.cardTop)

        // A 58 mm code, quiet zone included, pulled 5 mm up and left of the content box.
        val qr = page.ops.filterIsInstance<Op.Qr>().single()
        near(mm(58f), qr.size)
        near(page.cardLeft + mm(12f) - mm(5f), qr.x)
        near(page.cardTop + mm(10f) + 20f * 1.45f + mm(1f) + 9f * 1.45f + mm(6f) - mm(5f), qr.y)

        // The 50 mm calibration bar, ticks every 10 mm and one flush with its right end.
        val bar = page.boxes().single { abs(it.height - mm(1.2f)) < 0.01f }
        near(mm(50f), bar.width)
        val ticks = page.boxes().filter { abs(it.width - mm(0.25f)) < 0.01f }
        assertEquals(6, ticks.size)
        ticks.forEach { near(mm(5f), it.height) }
        assertEquals(listOf(0f, 10f, 20f, 30f, 40f).map { bar.x + mm(it) } + (bar.x + mm(49.75f)), ticks.map { it.x })
        near(bar.x + bar.width, ticks.last().x + ticks.last().width)

        // Four L-shaped cut marks, 6 mm by 0.3 mm, at the card's corners.
        val horizontal = page.boxes().filter { abs(it.width - mm(6f)) < 0.01f && abs(it.height - mm(0.3f)) < 0.01f }
        val vertical = page.boxes().filter { abs(it.width - mm(0.3f)) < 0.01f && abs(it.height - mm(6f)) < 0.01f }
        assertEquals(4, horizontal.size)
        assertEquals(4, vertical.size)
        near(page.cardLeft, horizontal.minOf { it.x })
        near(page.cardRight, horizontal.maxOf { it.x + it.width })
        near(page.cardTop, horizontal.minOf { it.y })
        near(page.cardBottom, horizontal.maxOf { it.y + it.height })
    }

    @Test
    fun `the page says everything the Go sheet says`() {
        val texts = RecoverySheet.layout(content, measure).texts()
        val strings = texts.map { it.text }

        assertTrue("Recovery secret" in strings)
        assertTrue("Voidbind identity · written 25 September 2026" in strings)
        assertEquals(content.groups, texts.filter { it.style == RecoverySheet.Styles.Secret }.map { it.text })
        assertTrue("Fingerprint " in strings)
        assertEquals(user.fingerprint, texts.single { it.style == RecoverySheet.Styles.Fingerprint }.text)
        // The user ID wraps anywhere (break-all), losing nothing.
        val uid = texts.filter { it.style == RecoverySheet.Styles.UserId }.joinToString("") { it.text }
        assertEquals(user.userId.render(), uid)
        assertTrue(listOf("1. ", "2. ", "3. ", "4. ").all { it in strings })
        val noteWords = texts.filter { it.style == RecoverySheet.Styles.Note && !it.text.matches(Regex("\\d\\. ")) }
            .joinToString(" ") { it.text }
        assertEquals(content.notes.joinToString(" "), noteWords)
        val calibration = texts.filter { it.style == RecoverySheet.Styles.Ruler }.joinToString(" ") { it.text }
        assertEquals(RecoverySheet.CALIBRATION, calibration)
        assertTrue(calibration.startsWith("This bar must measure exactly 50 mm"))
    }

    @Test
    fun `the groups sit four to a row beside the code, inside the card`() {
        val page = RecoverySheet.layout(content, measure)
        val qr = page.ops.filterIsInstance<Op.Qr>().single()
        val groups = page.texts().filter { it.style == RecoverySheet.Styles.Secret }

        assertEquals(content.groups.chunked(4).map { it.size }, groups.groupBy { it.baseline }.values.map { it.size })
        groups.forEach {
            assertTrue(it.x >= qr.x + qr.size + mm(8f) - 0.01f)
            assertTrue(it.x + measure.width(it.text, it.style) <= page.cardRight - mm(12f))
        }
    }

    @Test
    fun `the card fits inside the margins of A4 and of Letter`() {
        for ((w, h) in listOf(595f to 842f, 612f to 792f)) {
            val page = RecoverySheet.layout(content, measure, w, h)
            assertTrue(page.cardLeft >= mm(12f) && page.cardRight <= w - mm(12f), "card too wide for $w")
            assertTrue(page.cardBottom <= h - mm(12f), "card too tall for $h: ${page.cardBottom}")
            for (op in page.ops) {
                val (x, y) = when (op) {
                    is Op.Text -> op.x to op.baseline
                    is Op.Box -> op.x + op.width to op.y + op.height
                    is Op.Qr -> op.x + op.size to op.y + op.size
                }
                assertTrue(x in 0f..w && y in 0f..h, "$op is off the page")
            }
            near(mm(58f), page.ops.filterIsInstance<Op.Qr>().single().size)
        }
    }
}
