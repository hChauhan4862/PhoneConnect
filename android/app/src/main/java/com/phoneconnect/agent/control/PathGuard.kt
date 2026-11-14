package com.phoneconnect.agent.control

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/**
 * Why a requested path never became a filesystem operation. [code] is the stable machine code
 * the command result carries, so the UI can say exactly what was refused.
 */
class PathError(val code: String, message: String) : Exception(message) {
    companion object {
        /** The request itself is unusable: a NUL byte, or a symlink that cannot be resolved. */
        const val INVALID: String = "invalid_path"

        /** The request would reach outside the one shared root. */
        const val OUTSIDE_ROOT: String = "path_outside_root"
    }
}

/**
 * The only way a file command turns a user string into a path.
 *
 * One configured directory is the whole namespace: a request is a path relative to it.
 * Absolute paths, any `..` component, NUL bytes, and symlinks whose real target leaves the
 * root are refused before the filesystem is touched. The returned path is the *real* path, so
 * an accepted request names one concrete file and the handlers never see the request string
 * again; a link that stays inside the root is followed, so an operation acts on its target.
 */
class PathGuard(root: File) {
    private val rootPath: Path = root.toPath().toAbsolutePath().normalize()

    /**
     * The root as the filesystem sees it: every accepted path is checked against this.
     * Prepared on first use, not at construction, so a service that composes a guard can never
     * fail to start because of a storage hiccup — the command that needs a file says so.
     */
    private val preparedRoot: Path by lazy {
        if (!Files.isDirectory(rootPath)) Files.createDirectories(rootPath)
        rootPath.toRealPath()
    }

    init {
        require(rootPath.parent != null) { "the shared file root may not be the filesystem root" }
    }

    /** The shared root itself, used to report entries relative to it. */
    fun root(): Path = requireRoot()

    /** The request form of an accepted [path]: root-relative, `/`-separated, `""` for the root. */
    fun relative(path: Path): String =
        requireRoot().relativize(path).joinToString("/") { segment -> segment.toString() }

    private fun requireRoot(): Path = try {
        preparedRoot
    } catch (_: IOException) {
        throw PathError(PathError.INVALID, "the shared file root is unavailable")
    }

    /**
     * Resolves one request inside the root, or refuses it with a [PathError].
     *
     * The deepest existing ancestor is resolved with symlinks followed and checked against the
     * root, so a link that leaves the root is refused even when the rest of the path does not
     * exist yet (which is what a write or a mkdir needs).
     */
    fun resolve(requested: String): Path {
        if (requested.indexOf('\u0000') >= 0) {
            throw PathError(PathError.INVALID, "a path may not contain a NUL byte")
        }
        if (requested.startsWith("/")) {
            throw PathError(PathError.OUTSIDE_ROOT, "a path must be relative to the shared root")
        }
        val realRoot = requireRoot()
        val segments = requested.split('/').filter { it.isNotEmpty() && it != "." }
        if (segments.any { it == ".." }) {
            throw PathError(PathError.OUTSIDE_ROOT, "a path may not contain \"..\"")
        }

        var existing = rootPath
        for (segment in segments) existing = existing.resolve(segment)

        val tail = ArrayDeque<String>()
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            val name = existing.fileName
                ?: throw PathError(PathError.OUTSIDE_ROOT, "a path must stay inside the shared root")
            tail.addFirst(name.toString())
            existing = existing.parent
                ?: throw PathError(PathError.OUTSIDE_ROOT, "a path must stay inside the shared root")
        }

        val real = try {
            existing.toRealPath()
        } catch (_: IOException) {
            // A link whose target is gone must not be written through: the target could be
            // created anywhere its own link points.
            throw PathError(PathError.INVALID, "\"$requested\" cannot be resolved")
        }
        if (!real.startsWith(realRoot)) {
            throw PathError(PathError.OUTSIDE_ROOT, "\"$requested\" leaves the shared root")
        }

        val resolved = tail.fold(real) { path, name -> path.resolve(name) }
        if (!resolved.startsWith(realRoot)) {
            throw PathError(PathError.OUTSIDE_ROOT, "\"$requested\" leaves the shared root")
        }
        return resolved
    }
}
