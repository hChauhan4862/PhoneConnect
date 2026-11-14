package com.phoneconnect.agent

import com.phoneconnect.agent.control.ReaderSlot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The frame-reader slot: which reader is installed, and which reader a caller still owns.
 *
 * This is where a close racing a resize is decided. The property that matters is that every
 * reader is released exactly once — no `ImageReader` (and its full-size native images) is ever
 * orphaned because `close()` and a failed resize both thought the other one owned it.
 */
class ReaderSlotTest {
    private class CountingReader {
        var closes = 0
            private set

        fun close() {
            closes += 1
        }
    }

    @Test
    fun `installing a reader returns the previous one for the caller to close`() {
        val first = CountingReader()
        val second = CountingReader()
        val slot = ReaderSlot(first)

        assertSame(first, slot.installed())
        assertSame(first, slot.install(second))
        assertSame(second, slot.installed())
        assertEquals(0, first.closes)
        assertTrue(slot.open)
    }

    @Test
    fun `detaching returns the installed reader once and closes the slot`() {
        val first = CountingReader()
        val slot = ReaderSlot(first)

        assertSame(first, slot.detach())
        assertFalse(slot.open)
        assertNull(slot.installed())
        assertNull("a second detach must not hand out the same reader again", slot.detach())
    }

    @Test
    fun `a resize that finishes after a close closes the reader it never installed`() {
        val installed = CountingReader()
        val replacement = CountingReader()
        val slot = ReaderSlot(installed)

        // The resize has already talked to the platform; a stop closes the mirror meanwhile.
        val detached = slot.detach()!!
        detached.close()

        // Publishing the replacement now must fail, and the caller must close it itself.
        assertSame(replacement, slot.install(replacement))
        replacement.close()

        assertEquals("the reader that was installed must be closed once", 1, installed.closes)
        assertEquals("the reader that was never installed must be closed once", 1, replacement.closes)
    }

    @Test
    fun `a failed resize closes only the replacement and leaves the mirror usable`() {
        val installed = CountingReader()
        val replacement = CountingReader()
        val slot = ReaderSlot(installed)

        // The platform refused the resize before anything was published.
        replacement.close()

        assertEquals(1, replacement.closes)
        assertEquals("the installed reader must stay", 0, installed.closes)
        assertSame(installed, slot.installed())
        assertTrue(slot.open)
    }

    @Test
    fun `a close during a failed resize still releases both readers exactly once`() {
        val installed = CountingReader()
        val replacement = CountingReader()
        val slot = ReaderSlot(installed)

        // The resize starts, the platform throws, and close() runs before the failure handler:
        // the installed reader is detached by close(), the replacement was never installed.
        val detached = slot.detach()
        detached?.close()
        replacement.close()
        // The failure handler runs afterwards; closing what it still owns must not double close.
        val stillInstalled = slot.installed()
        assertNull("nothing may be left installed", stillInstalled)

        assertEquals(1, installed.closes)
        assertEquals(1, replacement.closes)
    }
}
