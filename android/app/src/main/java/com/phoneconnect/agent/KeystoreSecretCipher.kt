package com.phoneconnect.agent

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Sealing failed; the caller must treat the enrollment as unusable. */
class EncryptionException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Reversible sealing of a secret before it is written anywhere. */
interface SecretCipher {
    fun seal(plaintext: ByteArray): ByteArray

    fun open(ciphertext: ByteArray): ByteArray
}

/**
 * AES-256-GCM under a key that is generated inside the Android Keystore and never leaves
 * it. Both the device credential and the identity private key are sealed with this key, so
 * the stored bytes are useless if copied off the device.
 *
 * The key does not require user authentication: the agent connects while the screen is off,
 * and the point here is at-rest protection against other apps and backups, not a biometric
 * gate.
 */
class KeystoreSecretCipher(
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) },
) : SecretCipher {
    private val key: SecretKey by lazy { existingKeyOrCreate() }

    override fun seal(plaintext: ByteArray): ByteArray = try {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.iv + cipher.doFinal(plaintext)
    } catch (error: GeneralSecurityException) {
        throw EncryptionException("could not seal an enrollment secret", error)
    }

    override fun open(ciphertext: ByteArray): ByteArray = try {
        if (ciphertext.size <= IV_BYTES) {
            throw EncryptionException("sealed blob is too short to hold an IV")
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, ciphertext, 0, IV_BYTES))
        cipher.doFinal(ciphertext, IV_BYTES, ciphertext.size - IV_BYTES)
    } catch (error: GeneralSecurityException) {
        throw EncryptionException("could not open an enrollment secret", error)
    }

    private fun existingKeyOrCreate(): SecretKey {
        val existing = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "phoneconnect.enrollment"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
        const val TAG_BITS = 128
    }
}
