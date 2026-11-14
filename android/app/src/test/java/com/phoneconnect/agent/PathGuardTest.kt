package com.phoneconnect.agent

import com.phoneconnect.agent.control.PathError
import com.phoneconnect.agent.control.PathGuard
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files
import java.nio.file.Path

/**
 * Path safety is what makes file commands safe to expose: every accepted path is concrete,
 * stays inside one configured root, and no traversal, NUL, or escaping symlink gets through.
 */
class PathGuardTest {
    @get:Rule
    val temp = TemporaryFolder()

    private lateinit var realRoot: Path
    private lateinit var guard: PathGuard

    @Before
    fun setUp() {
        // The platform temp directory is itself reached through a symlink on macOS, so the
        // expectation is the real path, exactly as the guard reports it.
        realRoot = temp.newFolder("shared").toPath().toRealPath()
        guard = PathGuard(realRoot.toFile())
    }

    @Test
    fun `a legitimate nested path resolves under the root`() {
        val expected = realRoot.resolve("photos/2026/img.jpg")

        assertEquals(expected, guard.resolve("photos/2026/img.jpg"))
        assertEquals("redundant separators and dots do not change the target", expected, guard.resolve("./photos//2026/img.jpg"))
        assertEquals(realRoot, guard.resolve(""))
        assertEquals(realRoot, guard.resolve("."))
    }

    @Test
    fun `a parent component is refused even when it would land inside the root`() {
        assertEquals(PathError.OUTSIDE_ROOT, refusal("photos/../secrets").code)
        assertEquals(PathError.OUTSIDE_ROOT, refusal("..").code)
        assertEquals(PathError.OUTSIDE_ROOT, refusal("a/../../b").code)
    }

    @Test
    fun `an absolute path is refused`() {
        assertEquals(PathError.OUTSIDE_ROOT, refusal("/etc/passwd").code)
    }

    @Test
    fun `a NUL byte is refused`() {
        assertEquals(PathError.INVALID, refusal("notes\u0000.txt").code)
    }

    @Test
    fun `a symlink that leaves the root is refused`() {
        val outside = temp.newFolder("outside").toPath()
        Files.write(outside.resolve("secret.txt"), "top secret".toByteArray())
        Files.createSymbolicLink(realRoot.resolve("escape"), outside)

        assertEquals(PathError.OUTSIDE_ROOT, refusal("escape").code)
        assertEquals(PathError.OUTSIDE_ROOT, refusal("escape/secret.txt").code)
    }

    @Test
    fun `a symlink that stays inside the root resolves to its target`() {
        Files.createDirectories(realRoot.resolve("real"))
        Files.createSymbolicLink(realRoot.resolve("alias"), realRoot.resolve("real"))

        assertEquals(realRoot.resolve("real/file.txt"), guard.resolve("alias/file.txt"))
    }

    @Test
    fun `a dangling symlink is refused rather than written through`() {
        Files.createSymbolicLink(realRoot.resolve("broken"), realRoot.resolve("missing/file"))

        assertEquals(PathError.INVALID, refusal("broken").code)
    }

    @Test
    fun `a path that does not exist yet resolves under the existing root`() {
        assertEquals(realRoot.resolve("not/created/yet.txt"), guard.resolve("not/created/yet.txt"))
    }

    @Test
    fun `a root that is the filesystem root is refused`() {
        assertThrows(IllegalArgumentException::class.java) { PathGuard(File("/")) }
    }

    private fun refusal(requested: String): PathError = try {
        guard.resolve(requested)
        throw AssertionError("\"$requested\" should have been refused")
    } catch (error: PathError) {
        error
    }
}
