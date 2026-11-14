package com.phoneconnect.agent.control

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.DirectoryIteratorException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.Base64

/**
 * The six `files.*` commands, against the one shared root.
 *
 * Every path goes through [PathGuard] first, so a handler never touches a raw request string.
 * Reads are chunked and say honestly whether more remains; writes are capped by decoded size
 * and report exactly what they wrote; delete removes a file or an *empty* directory and is
 * never recursive. Failures are [CommandFailure]s carrying the machine code the UI shows.
 */
class FileHandler(private val guard: PathGuard) {
    /** Routes one command name this handler owns. */
    fun handle(name: String, args: JSONObject?): JSONObject = when (name) {
        CommandDispatcher.FILES_LIST -> list(args)
        CommandDispatcher.FILES_READ -> read(args)
        CommandDispatcher.FILES_WRITE -> write(args)
        CommandDispatcher.FILES_MKDIR -> mkdir(args)
        CommandDispatcher.FILES_DELETE -> delete(args)
        CommandDispatcher.FILES_RENAME -> rename(args)
        else -> throw CommandFailure.unknown(name)
    }

    fun list(args: JSONObject?): JSONObject {
        val path = path(args)
        if (!Files.exists(path)) throw notFound(path)
        if (!Files.isDirectory(path)) {
            throw CommandFailure("not_a_directory", "${display(path)} is not a directory")
        }

        val entries = ArrayList<JSONObject>()
        var encodedBytes = 0
        try {
            Files.newDirectoryStream(path).use { children ->
                for (child in children) {
                    val entry = describe(child) ?: continue
                    // One listing is one command result, and the server accepts at most 2 MiB.
                    // Measure UTF-8 bytes, not characters: org.json emits non-ASCII raw, so a
                    // character count would let a multi-byte listing out two to three times
                    // larger than it looks and take the channel down with it. Stop before
                    // materializing an oversized answer and say so; a silently truncated
                    // listing would be a fabricated one.
                    val encoded = entry.toString().toByteArray(Charsets.UTF_8).size + 1
                    if (entries.size >= MAX_LIST_ENTRIES || encodedBytes + encoded > MAX_LIST_BYTES) {
                        throw listingTooLarge(path)
                    }
                    encodedBytes += encoded
                    entries.add(entry)
                }
            }
        } catch (error: DirectoryIteratorException) {
            // Iteration wraps its own I/O fault; report it like the open, never as an
            // `internal_error` carrying the platform's absolute path.
            throw ioFailureForList(path, error)
        } catch (error: IOException) {
            throw ioFailureForList(path, error)
        }
        return JSONObject().put(
            "entries",
            JSONArray(entries.sortedBy { entry -> entry.getString("name") }),
        )
    }

    fun read(args: JSONObject?): JSONObject {
        val path = path(args)
        val offset = optionalLong(args, "offset", 0L)
        val length = optionalLong(args, "length", MAX_READ_BYTES.toLong())
        if (offset < 0) throw CommandFailure.invalid("offset must not be negative")
        if (length < 0) throw CommandFailure.invalid("length must not be negative")
        if (!Files.exists(path)) throw notFound(path)
        if (Files.isDirectory(path)) {
            throw CommandFailure("not_a_file", "${display(path)} is a directory")
        }

        val size = try {
            Files.size(path)
        } catch (error: IOException) {
            throw ioFailure("read", path, error)
        }
        val start = offset.coerceAtMost(size)
        val count = minOf(length, (size - start)).coerceAtMost(MAX_READ_BYTES.toLong()).toInt()
        val bytes = ByteArray(count)
        if (count > 0) {
            try {
                RandomAccessFile(path.toFile(), "r").use { file ->
                    file.seek(start)
                    file.readFully(bytes)
                }
            } catch (error: IOException) {
                throw ioFailure("read", path, error)
            }
        }
        return JSONObject()
            .put("data_base64", Base64.getEncoder().encodeToString(bytes))
            .put("truncated", start + count < size)
            .put("name", path.fileName?.toString() ?: "")
    }

    fun write(args: JSONObject?): JSONObject {
        val path = path(args)
        val encoded = requiredString(args, "data_base64")
        val append = optionalBoolean(args, "append", false)
        // Refuse an oversized payload before allocating its decoded form.
        if (encoded.length > MAX_ENCODED_BYTES) throw tooLarge()
        val bytes = try {
            Base64.getDecoder().decode(encoded)
        } catch (_: IllegalArgumentException) {
            throw CommandFailure.invalid("data_base64 is not valid base64")
        }
        if (bytes.size > MAX_WRITE_BYTES) throw tooLarge()
        requireNotRoot(path)
        if (Files.isDirectory(path)) {
            throw CommandFailure("is_directory", "${display(path)} is a directory")
        }
        requireParent(path)
        try {
            if (append) {
                Files.write(path, bytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND)
            } else {
                Files.write(
                    path,
                    bytes,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING,
                )
            }
        } catch (error: IOException) {
            throw ioFailure("write", path, error)
        }
        return JSONObject().put("bytes_written", bytes.size)
    }

    fun mkdir(args: JSONObject?): JSONObject {
        val path = path(args)
        requireNotRoot(path)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw CommandFailure("already_exists", "${display(path)} already exists")
        }
        requireParent(path)
        try {
            Files.createDirectory(path)
        } catch (error: IOException) {
            throw ioFailure("mkdir", path, error)
        }
        return JSONObject()
    }

    fun delete(args: JSONObject?): JSONObject {
        val path = path(args)
        requireNotRoot(path)
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw notFound(path)
        try {
            if (Files.isDirectory(path)) {
                val empty = Files.newDirectoryStream(path).use { children ->
                    !children.iterator().hasNext()
                }
                if (!empty) {
                    throw CommandFailure("dir_not_empty", "${display(path)} is not empty")
                }
            }
            Files.delete(path)
        } catch (error: IOException) {
            throw ioFailure("delete", path, error)
        }
        return JSONObject()
    }

    fun rename(args: JSONObject?): JSONObject {
        val from = path(args, "from")
        val to = path(args, "to")
        requireNotRoot(from)
        requireNotRoot(to)
        if (!Files.exists(from, LinkOption.NOFOLLOW_LINKS)) throw notFound(from)
        if (Files.exists(to, LinkOption.NOFOLLOW_LINKS)) {
            throw CommandFailure("already_exists", "${display(to)} already exists")
        }
        requireParent(to)
        try {
            // Never replaces: a destination that appeared since the check above is a refusal,
            // not a silently destroyed file.
            Files.move(from, to)
        } catch (error: IOException) {
            throw ioFailure("rename", from, error)
        }
        return JSONObject()
    }

    private fun path(args: JSONObject?, key: String = "path"): Path {
        val requested = requiredString(args, key)
        return try {
            guard.resolve(requested)
        } catch (error: PathError) {
            throw CommandFailure(error.code, error.message ?: error.code)
        }
    }

    /**
     * One entry, or `null` when the root cannot serve it: a dangling or escaping link is
     * invisible rather than offered and then refused.
     */
    private fun describe(child: Path): JSONObject? {
        val real = runCatching { child.toRealPath() }.getOrNull() ?: return null
        if (!real.startsWith(guard.root())) return null
        val attributes = runCatching {
            Files.readAttributes(real, BasicFileAttributes::class.java)
        }.getOrNull() ?: return null
        return JSONObject()
            .put("name", child.fileName.toString())
            .put("path", guard.relative(real))
            .put("is_dir", attributes.isDirectory)
            // A directory has no file size; reporting its inode size would be a platform
            // detail, not a fact about its contents.
            .put("size_bytes", if (attributes.isDirectory) 0L else attributes.size())
            .put("modified_ms", attributes.lastModifiedTime().toMillis())
    }

    private fun requireNotRoot(path: Path) {
        if (path == guard.root()) {
            throw CommandFailure(PathError.INVALID, "the shared root cannot be changed")
        }
    }

    private fun requireParent(path: Path) {
        val parent = path.parent
        if (parent == null || !Files.isDirectory(parent)) {
            throw CommandFailure("not_found", "the parent directory does not exist")
        }
    }

    private fun notFound(path: Path) =
        CommandFailure("not_found", "${display(path)} does not exist")

    /** A path as the caller wrote it, relative to the shared root: never a device path. */
    private fun display(path: Path): String {
        val relative = guard.relative(path)
        return if (relative.isEmpty()) "\"\"" else "\"$relative\""
    }

    private fun tooLarge() = CommandFailure(
        "too_large",
        "a write may carry at most $MAX_WRITE_BYTES decoded bytes",
    )

    private fun listingTooLarge(path: Path) = CommandFailure(
        "listing_too_large",
        "${display(path)} has more entries than one listing may carry " +
            "(limit $MAX_LIST_ENTRIES entries or $MAX_LIST_BYTES bytes)",
    )

    /**
     * The refusal for a directory that could not be read or iterated. Kept separate so the
     * iteration wrapper's unwrapping is testable without provoking a real mid-iteration fault.
     */
    internal fun ioFailureForList(path: Path, error: Throwable): CommandFailure {
        val cause = when (error) {
            is DirectoryIteratorException ->
                error.cause as? IOException ?: IOException("directory iteration failed")
            is IOException -> error
            else -> IOException(error.message ?: error.javaClass.simpleName)
        }
        return ioFailure("list", path, cause)
    }

    private fun ioFailure(operation: String, path: Path, error: IOException): CommandFailure {
        // The platform message can name absolute device paths; the caller gets the operation
        // and the request instead.
        return CommandFailure(
            "io_error",
            "$operation failed for ${display(path)} (${error.javaClass.simpleName})",
        )
    }

    private fun requiredString(args: JSONObject?, key: String): String {
        val value = args?.opt(key) ?: throw CommandFailure.invalid("$key is required")
        if (value == JSONObject.NULL) throw CommandFailure.invalid("$key is required")
        if (value !is String) throw CommandFailure.invalid("$key must be a string")
        return value
    }

    private fun optionalLong(args: JSONObject?, key: String, fallback: Long): Long {
        val value = args?.opt(key) ?: return fallback
        if (value == JSONObject.NULL) return fallback
        if (value !is Number) throw CommandFailure.invalid("$key must be a number")
        return value.toLong()
    }

    private fun optionalBoolean(args: JSONObject?, key: String, fallback: Boolean): Boolean {
        val value = args?.opt(key) ?: return fallback
        if (value == JSONObject.NULL) return fallback
        if (value !is Boolean) throw CommandFailure.invalid("$key must be a boolean")
        return value
    }

    companion object {
        /** At most one chunk of decoded bytes per read response. */
        const val MAX_READ_BYTES: Int = 256 * 1024

        /** Entries one listing may carry before it is refused as `listing_too_large`. */
        const val MAX_LIST_ENTRIES: Int = 4_096

        /**
         * UTF-8 bytes of the serialized entries one listing may carry. The server refuses a
         * result above 2 MiB and closes the channel above a 2.16 MiB frame, so staying well
         * under both keeps `files.list` a usable answer instead of a dropped channel.
         */
        private const val MAX_LIST_BYTES: Int = 1_000_000

        /** At most one mebibyte of decoded bytes per write request. */
        const val MAX_WRITE_BYTES: Int = 1024 * 1024

        /** The base64 form of [MAX_WRITE_BYTES]: anything longer decodes past the cap. */
        private const val MAX_ENCODED_BYTES: Int = 4 * ((MAX_WRITE_BYTES + 2) / 3)
    }
}
