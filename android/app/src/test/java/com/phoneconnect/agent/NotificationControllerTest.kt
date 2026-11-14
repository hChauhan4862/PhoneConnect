package com.phoneconnect.agent

import android.app.Notification
import android.app.NotificationManager
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class NotificationControllerTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val manager = context.getSystemService(NotificationManager::class.java)
    private lateinit var controller: NotificationController

    @Before
    fun setUp() {
        controller = NotificationController(context, manager)
        controller.ensureChannel()
    }

    @Test
    fun `every status update reuses the one notification`() {
        controller.update(ConnectionStatus.Connecting(attempt = 1))
        controller.update(ConnectionStatus.Connected(ConnectionPath.DIRECT, sinceMs = 1_000))
        controller.update(
            ConnectionStatus.Reconnecting(attempt = 2, retryInMs = 4_000, reason = ReconnectReason.TRANSPORT_CLOSED),
        )
        controller.update(ConnectionStatus.Terminal(ConnectionFailure.DeviceRevoked))

        val shadow = shadowOf(manager)
        assertEquals("the agent must never stack notifications", 1, shadow.size())
        assertNotNull(shadow.getNotification(NotificationController.NOTIFICATION_ID))
        assertEquals(1, shadow.notificationChannels.size)
        assertEquals(NotificationController.CHANNEL_ID, shadow.notificationChannels.single().id)
    }

    @Test
    fun `a refused session names the action the operator can take`() {
        val scope = controller
            .text(ConnectionStatus.Terminal(ConnectionFailure.SessionRefused("session_scope_mismatch")))
            .lowercase()
        assertTrue("a scope refusal needs a new session: $scope", scope.contains("new session"))
        assertFalse("a scope refusal must not claim the device needs re-enrolling", scope.contains("enroll again"))

        // The server's own answer for a ticket with no pinned identity is that the device must
        // be re-enrolled; telling the operator to create a new session would be wrong.
        val identity = controller
            .text(ConnectionStatus.Terminal(ConnectionFailure.SessionRefused("ticket_identity_missing")))
            .lowercase()
        assertTrue("a missing identity needs re-enrollment: $identity", identity.contains("enroll this device again"))
        assertFalse("a missing identity is not fixed by a new session: $identity", identity.contains("new session"))
    }

    @Test
    fun `the connection notification is ongoing and quiet`() {
        val notification = controller.build(ConnectionStatus.Connected(ConnectionPath.RELAY, sinceMs = 0))

        assertTrue(
            "a foreground connection notification is ongoing",
            notification.flags and Notification.FLAG_ONGOING_EVENT != 0,
        )
        assertEquals(NotificationController.CHANNEL_ID, notification.channelId)
        assertEquals(
            "the connection channel must never make noise",
            NotificationManager.IMPORTANCE_LOW,
            manager.getNotificationChannel(NotificationController.CHANNEL_ID).importance,
        )
    }

    @Test
    fun `clearing removes the one notification`() {
        controller.update(ConnectionStatus.Connecting(attempt = 1))
        controller.clear()

        assertEquals(0, shadowOf(manager).size())
    }

    @Test
    fun `status text reports health and recovery without promising immortality`() {
        val statuses = listOf(
            ConnectionStatus.Connecting(attempt = 1),
            ConnectionStatus.Connected(ConnectionPath.DIRECT, sinceMs = 0),
            ConnectionStatus.Connected(ConnectionPath.RELAY, sinceMs = 0),
            ConnectionStatus.Reconnecting(1, 1_000, ReconnectReason.NETWORK_UNAVAILABLE),
            ConnectionStatus.Terminal(ConnectionFailure.DeviceRevoked),
            ConnectionStatus.Terminal(ConnectionFailure.NotEnrolled),
            ConnectionStatus.Unenrolled,
        )
        val texts = statuses.map { controller.text(it).lowercase() }

        val forbidden = listOf("will not be killed", "cannot be killed", "always running", "guaranteed", "immune")
        for ((index, text) in texts.withIndex()) {
            for (claim in forbidden) {
                assertFalse(
                    "status ${statuses[index]} must not promise persistence: ${text}",
                    text.contains(claim),
                )
            }
        }
        // The two connection paths are distinguishable, and retrying says what it is doing.
        assertTrue(texts[1].contains("direct"))
        assertTrue(texts[2].contains("relay"))
        assertTrue(texts[3].contains("retrying"))
        assertTrue(texts[0].contains("connecting"))
    }

    @Test
    fun `the agent posts its one notification through one id`() {
        val sources = mainKotlinSources()
        val startForeground = sources.flatMap { (path, text) ->
            Regex("""\bstartForeground\s*\(\s*([^,)\n]+)""").findAll(text).map { path to it.groupValues[1].trim() }
        }
        assertTrue("the service must post its foreground notification", startForeground.isNotEmpty())
        assertTrue(
            "the foreground notification must be posted by ConnectionService, found $startForeground",
            startForeground.all { it.first.substringAfterLast('/') == "ConnectionService.kt" },
        )

        val notify = sources.flatMap { (path, text) ->
            Regex("""\.notify\s*\(\s*([^,)\n]+)""").findAll(text).map { path to it.groupValues[1].trim() }
        }
        assertEquals("exactly one notify call site", 1, notify.size)

        val expressions = (startForeground + notify).map { it.second }
        val allowed = setOf("NOTIFICATION_ID", "NotificationController.NOTIFICATION_ID")
        assertTrue(
            "every notification post must use the one fixed id, found $expressions",
            expressions.all { it in allowed },
        )
        assertEquals(
            "there must be exactly one id, found $expressions",
            setOf("NOTIFICATION_ID"),
            expressions.map { it.substringAfterLast('.') }.toSet(),
        )

        val declarations = sources.values.sumOf { Regex("""const\s+val\s+NOTIFICATION_ID\b""").findAll(it).count() }
        assertEquals("the id must be declared exactly once", 1, declarations)
    }

    @Test
    fun `only the notification controller touches the notification APIs`() {
        val offenders = mainKotlinSources()
            .filterKeys { !it.endsWith("NotificationController.kt") }
            .filterValues { text ->
                text.contains("NotificationManager") ||
                    text.contains("NotificationChannel(") ||
                    text.contains("NotificationCompat.Builder")
            }
            .keys

        assertTrue(
            "notification state changed outside NotificationController: $offenders",
            offenders.isEmpty(),
        )
    }

    private fun mainKotlinSources(): Map<String, String> {
        val root = File("src/main/java")
        assertTrue("source root must exist at ${root.absolutePath}", root.isDirectory)
        return root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .associate { it.path to it.readText() }
    }
}
