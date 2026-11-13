package com.phoneconnect.agent

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject
import java.util.Base64

/**
 * Enrollment persisted as one JSON record whose two secrets are sealed by [SecretCipher]
 * (Android Keystore in production). The device id, state, and timestamps stay readable so
 * the status surface can explain what happened without decrypting anything.
 *
 * A record that cannot be read or opened is discarded rather than presented: an unusable
 * enrollment must look unenrolled, not healthy.
 */
@OptIn(IdentityBoundary::class)
class KeystoreEnrollmentStore(
    context: Context,
    private val cipher: SecretCipher = KeystoreSecretCipher(),
) : EnrollmentStore {
    private val preferences: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    override suspend fun info(): EnrollmentInfo? = withContext(Dispatchers.IO) {
        readRecord()?.toInfo()
    }

    override suspend fun lastClearReason(): ClearReason? = withContext(Dispatchers.IO) {
        preferences.getString(KEY_CLEAR_REASON, null)?.let { stored ->
            ClearReason.entries.firstOrNull { it.name == stored }
        }
    }

    override suspend fun enroll(request: EnrollmentRequest): Unit = withContext(Dispatchers.IO) {
        // Kotlin strings cannot be zeroed, so the credential becomes bytes once and those
        // bytes are wiped as soon as they are sealed.
        val credential = request.credential.toByteArray(Charsets.UTF_8)
        val privateKey = request.identityPrivateKey.copyOf()
        try {
            val record = JSONObject()
                .put(FIELD_VERSION, FORMAT_VERSION)
                .put(FIELD_DEVICE_ID, request.deviceId)
                .put(FIELD_STATE, EnrollmentState.ENROLLED.name)
                .put(FIELD_ENROLLED_AT_MS, request.enrolledAtMs)
                .put(FIELD_CREDENTIAL, encode(seal(credential, "credential")))
                .put(FIELD_PRIVATE_KEY, encode(seal(privateKey, "identity private key")))
                .put(FIELD_PUBLIC_KEY, encode(request.identityPublicKey))

            // A failed seal throws before this line, so a half enrollment is never written.
            // The write is committed synchronously and read back: reporting an enrollment
            // that did not reach disk would leave the agent retrying a credential it does
            // not have.
            val raw = record.toString()
            preferences.edit(commit = true) { putString(KEY_RECORD, raw) }
            if (preferences.getString(KEY_RECORD, null) != raw) {
                throw EnrollmentStorageException("could not persist the enrollment record")
            }
            preferences.edit(commit = true) { remove(KEY_CLEAR_REASON) }
        } finally {
            credential.fill(0)
            privateKey.fill(0)
        }
    }

    override suspend fun openIdentity(): DeviceIdentity? = withContext(Dispatchers.IO) {
        val record = readRecord() ?: return@withContext null
        if (record.state != EnrollmentState.ENROLLED) return@withContext null
        try {
            DeviceIdentity(
                deviceId = record.deviceId,
                credentialBytes = cipher.open(record.credential),
                privateKeyBytes = cipher.open(record.privateKey),
                identityPublicKey = decode(record.publicKey),
            )
        } catch (error: EncryptionException) {
            // The Keystore key is gone or was invalidated (for example after a device
            // credential change). The stored material is useless; drop it and report
            // unenrolled instead of looping on a credential that can never be read.
            clearRecord(ClearReason.UNREADABLE)
            null
        }
    }

    override suspend fun clear(reason: ClearReason): Boolean = withContext(Dispatchers.IO) {
        clearRecord(reason)
    }

    private fun clearRecord(reason: ClearReason): Boolean {
        preferences.edit(commit = true) {
            remove(KEY_RECORD)
            putString(KEY_CLEAR_REASON, reason.name)
        }
        if (preferences.contains(KEY_RECORD)) {
            throw EnrollmentStorageException("could not clear the enrollment record")
        }
        return true
    }

    private fun seal(plaintext: ByteArray, what: String): ByteArray = try {
        cipher.seal(plaintext)
    } catch (error: EncryptionException) {
        throw EnrollmentStorageException("could not seal the $what at rest", error)
    }

    private fun readRecord(): Record? {
        val raw = preferences.getString(KEY_RECORD, null) ?: return null
        val json = try {
            JSONObject(raw)
        } catch (error: JSONException) {
            clearRecord(ClearReason.UNREADABLE)
            return null
        }
        if (json.optInt(FIELD_VERSION) != FORMAT_VERSION) {
            clearRecord(ClearReason.UNREADABLE)
            return null
        }
        val state = EnrollmentState.entries.firstOrNull { it.name == json.optString(FIELD_STATE) }
        val deviceId = json.optString(FIELD_DEVICE_ID)
        if (state == null || deviceId.isEmpty()) {
            clearRecord(ClearReason.UNREADABLE)
            return null
        }
        return try {
            Record(
                deviceId = deviceId,
                state = state,
                enrolledAtMs = json.getLong(FIELD_ENROLLED_AT_MS),
                credential = decode(json.getString(FIELD_CREDENTIAL)),
                privateKey = decode(json.getString(FIELD_PRIVATE_KEY)),
                publicKey = json.getString(FIELD_PUBLIC_KEY),
            )
        } catch (error: JSONException) {
            clearRecord(ClearReason.UNREADABLE)
            null
        } catch (error: IllegalArgumentException) {
            clearRecord(ClearReason.UNREADABLE)
            null
        }
    }

    private fun Record.toInfo() = EnrollmentInfo(deviceId = deviceId, state = state, enrolledAtMs = enrolledAtMs)

    private fun encode(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun decode(value: String): ByteArray = Base64.getDecoder().decode(value)

    private data class Record(
        val deviceId: String,
        val state: EnrollmentState,
        val enrolledAtMs: Long,
        val credential: ByteArray,
        val privateKey: ByteArray,
        val publicKey: String,
    )

    companion object {
        /** Preferences file holding the enrollment record. */
        const val PREFERENCES_NAME = "phoneconnect.enrollment"

        private const val KEY_RECORD = "record"
        private const val KEY_CLEAR_REASON = "last_clear_reason"
        private const val FORMAT_VERSION = 1
        private const val FIELD_VERSION = "version"
        private const val FIELD_DEVICE_ID = "device_id"
        private const val FIELD_STATE = "state"
        private const val FIELD_ENROLLED_AT_MS = "enrolled_at_ms"
        private const val FIELD_CREDENTIAL = "credential"
        private const val FIELD_PRIVATE_KEY = "identity_private_key"
        private const val FIELD_PUBLIC_KEY = "identity_public_key"
    }
}
