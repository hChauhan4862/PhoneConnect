package com.phoneconnect.agent

import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.LogcatHandler
import com.phoneconnect.agent.control.ShellHandler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `shell.exec` and `logcat.tail` exist so a caller receives a machine code, not
 * `unknown_command`. Neither can honestly succeed for an ordinary installed app, so each is a
 * constant refusal that names the platform restriction.
 */
class RefusalHandlersTest {
    @Test
    fun `shell exec is a constant not_permitted refusal naming the platform restriction`() {
        val failure = assertThrows(CommandFailure::class.java) { ShellHandler().exec() }

        assertEquals("not_permitted", failure.code)
        val message = failure.message.orEmpty()
        assertTrue("the message must name the shell restriction: $message", message.contains("shell"))
        assertTrue("the message must name what would be needed: $message", message.contains("privileged"))
        assertFalse("a message must not name a device path: $message", message.contains("/"))
        assertFalse("a message must not carry exception text: $message", message.contains("Exception"))
    }

    @Test
    fun `logcat tail is a constant not_permitted refusal naming READ_LOGS`() {
        val failure = assertThrows(CommandFailure::class.java) { LogcatHandler().tail() }

        assertEquals("not_permitted", failure.code)
        val message = failure.message.orEmpty()
        assertTrue("the message must name the log restriction: $message", message.contains("log"))
        assertTrue("the message must name the permission level: $message", message.contains("READ_LOGS"))
        assertTrue("the message must say it is signature-level: $message", message.contains("signature"))
        assertFalse("a message must not name a device path: $message", message.contains("/"))
        assertFalse("a message must not carry exception text: $message", message.contains("Exception"))
    }
}
