package one.rarebit.cruciform.desktop.ui

import kotlin.test.Test
import kotlin.test.assertEquals

/** A site or op can send any Long as a time: the UI shows it, never throws. */
class TimestampTest {
    @Test
    fun anInRangeTimeIsFormatted() = assertEquals("2026-01-02T04:04:05Z", timestamp(1_767_326_645))

    @Test
    fun anOutOfRangeTimeIsShownRawNotThrown() {
        assertEquals("${Long.MAX_VALUE} (unix seconds, out of range)", timestamp(Long.MAX_VALUE))
        assertEquals("${Long.MIN_VALUE} (unix seconds, out of range)", timestamp(Long.MIN_VALUE))
    }
}
