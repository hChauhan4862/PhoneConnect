package com.phoneconnect.agent

import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.FileHandler
import com.phoneconnect.agent.control.PathGuard
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.Base64

/**
 * The six file commands against a real directory tree: every answer is the operation's honest
 * result, a chunk never exceeds its cap, and every refusal is the machine code the web shows.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class FileHandlerTest {
    @get:Rule
    val temp = TemporaryFolder()

    private lateinit var root: File
    private lateinit var handler: FileHandler

    @Before
    fun setUp() {
        root = temp.newFolder("shared")
        handler = FileHandler(PathGuard(root))
    }

    @Test
    fun `listing reports the fields the browser renders`() {
        writeFile("b.txt", "hello".toByteArray())
        File(root, "folder").mkdirs()

        val entries = handler.list(args("path" to "")).getJSONArray("entries")

        assertEquals(2, entries.length())
        val file = entries.getJSONObject(0)
        assertEquals("b.txt", file.getString("name"))
        assertEquals("b.txt", file.getString("path"))
        assertEquals(false, file.getBoolean("is_dir"))
        assertEquals(5L, file.getLong("size_bytes"))
        assertTrue("a modification time came from the platform", file.getLong("modified_ms") > 0)
        val directory = entries.getJSONObject(1)
        assertEquals("folder", directory.getString("name"))
        assertEquals(true, directory.getBoolean("is_dir"))
        assertEquals("a directory reports no file size", 0L, directory.getLong("size_bytes"))
    }

    @Test
    fun `listing a nested directory reports root-relative paths`() {
        writeFile("folder/nested.txt", "x".toByteArray())

        val entries = handler.list(args("path" to "folder")).getJSONArray("entries")

        assertEquals(1, entries.length())
        assertEquals("folder/nested.txt", entries.getJSONObject(0).getString("path"))
    }

    @Test
    fun `listing an empty directory is an empty list, not an error`() {
        File(root, "empty").mkdirs()
        assertEquals(0, handler.list(args("path" to "empty")).getJSONArray("entries").length())
    }

    @Test
    fun `listing a file or a missing directory is refused`() {
        writeFile("a.txt", "x".toByteArray())

        assertEquals("not_a_directory", failure { handler.list(args("path" to "a.txt")) }.code)
        assertEquals("not_found", failure { handler.list(args("path" to "missing")) }.code)
    }

    @Test
    fun `listing outside the root is refused`() {
        assertEquals("path_outside_root", failure { handler.list(args("path" to "../")) }.code)
    }

    @Test
    fun `reading returns base64 and an honest truncation flag`() {
        val content = ByteArray(300 * 1024) { (it % 251).toByte() }
        writeFile("big.bin", content)

        val first = handler.read(args("path" to "big.bin"))
        val firstBytes = Base64.getDecoder().decode(first.getString("data_base64"))

        assertEquals(FileHandler.MAX_READ_BYTES, firstBytes.size)
        assertArrayEquals(content.copyOfRange(0, FileHandler.MAX_READ_BYTES), firstBytes)
        assertEquals(true, first.getBoolean("truncated"))
        assertEquals("big.bin", first.getString("name"))

        val second = handler.read(args("path" to "big.bin", "offset" to firstBytes.size))
        val secondBytes = Base64.getDecoder().decode(second.getString("data_base64"))

        assertArrayEquals(
            content.copyOfRange(FileHandler.MAX_READ_BYTES, content.size),
            secondBytes,
        )
        assertEquals("the last chunk is not truncated", false, second.getBoolean("truncated"))
    }

    @Test
    fun `a requested length is clamped to one chunk`() {
        writeFile("big.bin", ByteArray(300 * 1024) { 7 })

        val output = handler.read(args("path" to "big.bin", "offset" to 0, "length" to 10_000_000))

        assertEquals(
            FileHandler.MAX_READ_BYTES,
            Base64.getDecoder().decode(output.getString("data_base64")).size,
        )
        assertEquals(true, output.getBoolean("truncated"))
    }

    @Test
    fun `reading past the end is empty and not truncated`() {
        writeFile("small.txt", "hello".toByteArray())

        val output = handler.read(args("path" to "small.txt", "offset" to 4_096))

        assertEquals(0, Base64.getDecoder().decode(output.getString("data_base64")).size)
        assertEquals(false, output.getBoolean("truncated"))
    }

    @Test
    fun `a negative offset or length is invalid_args`() {
        writeFile("small.txt", "hello".toByteArray())

        assertEquals(
            "invalid_args",
            failure { handler.read(args("path" to "small.txt", "offset" to -1)) }.code,
        )
        assertEquals(
            "invalid_args",
            failure { handler.read(args("path" to "small.txt", "length" to -1)) }.code,
        )
    }

    @Test
    fun `reading a directory is not_a_file`() {
        File(root, "folder").mkdirs()

        assertEquals("not_a_file", failure { handler.read(args("path" to "folder")) }.code)
        assertEquals("not_found", failure { handler.read(args("path" to "missing.txt")) }.code)
    }

    @Test
    fun `writing creates a file and reports the byte count`() {
        val output = handler.write(
            args("path" to "new.txt", "data_base64" to base64("hello".toByteArray())),
        )

        assertEquals(5, output.getInt("bytes_written"))
        assertArrayEquals("hello".toByteArray(), File(root, "new.txt").readBytes())
    }

    @Test
    fun `a write replaces the file unless it is told to append`() {
        writeFile("log.txt", "one".toByteArray())

        handler.write(args("path" to "log.txt", "data_base64" to base64("two".toByteArray())))
        assertEquals("two", File(root, "log.txt").readText())

        handler.write(
            args(
                "path" to "log.txt",
                "data_base64" to base64("+three".toByteArray()),
                "append" to true,
            ),
        )
        assertEquals("two+three", File(root, "log.txt").readText())
    }

    @Test
    fun `a write over one mebibyte is too_large and touches nothing`() {
        val payload = ByteArray(FileHandler.MAX_WRITE_BYTES + 1)

        val refused = failure {
            handler.write(args("path" to "huge.bin", "data_base64" to base64(payload)))
        }

        assertEquals("too_large", refused.code)
        assertFalse("a refused write must not create the file", File(root, "huge.bin").exists())
    }

    @Test
    fun `invalid base64 is invalid_args`() {
        assertEquals(
            "invalid_args",
            failure { handler.write(args("path" to "x.bin", "data_base64" to "not base64!")) }.code,
        )
    }

    @Test
    fun `a write cannot escape the root`() {
        val refused = failure {
            handler.write(
                args("path" to "../escape.txt", "data_base64" to base64("x".toByteArray())),
            )
        }

        assertEquals("path_outside_root", refused.code)
        assertFalse(File(root.parentFile, "escape.txt").exists())
    }

    @Test
    fun `writing into a missing parent is not_found`() {
        assertEquals(
            "not_found",
            failure {
                handler.write(
                    args("path" to "missing/a.txt", "data_base64" to base64("x".toByteArray())),
                )
            }.code,
        )
    }

    @Test
    fun `mkdir creates one directory and refuses an existing path`() {
        handler.mkdir(args("path" to "new"))
        assertTrue(File(root, "new").isDirectory)

        assertEquals("already_exists", failure { handler.mkdir(args("path" to "new")) }.code)
        assertEquals(
            "not_found",
            failure { handler.mkdir(args("path" to "missing/deeper")) }.code,
        )
    }

    @Test
    fun `delete removes a file`() {
        writeFile("gone.txt", "x".toByteArray())

        handler.delete(args("path" to "gone.txt"))

        assertFalse(File(root, "gone.txt").exists())
    }

    @Test
    fun `delete removes an empty directory and refuses a non-empty one`() {
        File(root, "empty").mkdirs()
        handler.delete(args("path" to "empty"))
        assertFalse(File(root, "empty").exists())

        writeFile("full/keep.txt", "x".toByteArray())
        assertEquals("dir_not_empty", failure { handler.delete(args("path" to "full")) }.code)
        assertTrue("a refusal deletes nothing", File(root, "full/keep.txt").exists())
    }

    @Test
    fun `delete refuses the shared root and a missing path`() {
        assertEquals("invalid_path", failure { handler.delete(args("path" to "")) }.code)
        assertEquals("not_found", failure { handler.delete(args("path" to "nope")) }.code)
        assertTrue("the shared root survives a delete request", root.isDirectory)
    }

    @Test
    fun `rename moves a file and a directory`() {
        writeFile("before.txt", "x".toByteArray())
        File(root, "old-dir").mkdirs()

        handler.rename(args("from" to "before.txt", "to" to "nested/after.txt").also {
            File(root, "nested").mkdirs()
        })
        assertFalse(File(root, "before.txt").exists())
        assertEquals("x", File(root, "nested/after.txt").readText())

        handler.rename(args("from" to "old-dir", "to" to "new-dir"))
        assertTrue(File(root, "new-dir").isDirectory)
    }

    @Test
    fun `rename refuses an existing destination and a missing source`() {
        writeFile("a.txt", "a".toByteArray())
        writeFile("b.txt", "b".toByteArray())

        assertEquals(
            "already_exists",
            failure { handler.rename(args("from" to "a.txt", "to" to "b.txt")) }.code,
        )
        assertEquals(
            "an existing file is never replaced",
            "b",
            File(root, "b.txt").readText(),
        )
        assertEquals(
            "not_found",
            failure { handler.rename(args("from" to "missing", "to" to "x")) }.code,
        )
    }

    @Test
    fun `rename refuses to move the shared root`() {
        assertEquals(
            "invalid_path",
            failure { handler.rename(args("from" to "", "to" to "elsewhere")) }.code,
        )
        assertTrue(root.isDirectory)
    }

    private fun args(vararg pairs: Pair<String, Any?>): JSONObject = JSONObject().apply {
        pairs.forEach { (key, value) -> put(key, value) }
    }

    private fun failure(block: () -> JSONObject): CommandFailure = try {
        block()
        throw AssertionError("expected a refusal")
    } catch (error: CommandFailure) {
        error
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun writeFile(name: String, bytes: ByteArray): File =
        File(root, name).apply {
            parentFile?.mkdirs()
            writeBytes(bytes)
        }
}
