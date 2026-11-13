package com.phoneconnect.agent

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.Base64

@OptIn(IdentityBoundary::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EnrollmentStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val credential = "pcdev_SuperSecretCredentialValue"
    private val privateKey = ByteArray(32) { (it + 1).toByte() }
    private val publicKey = ByteArray(32) { (it + 101).toByte() }
    private lateinit var cipher: FakeSecretCipher
    private lateinit var store: KeystoreEnrollmentStore

    @Before
    fun setUp() {
        cipher = FakeSecretCipher()
        store = KeystoreEnrollmentStore(context, cipher)
    }

    @Test
    fun `an enrolled identity round-trips through the boundary`() = runTest {
        store.enroll(request())

        val info = store.info()
        assertNotNull(info)
        assertEquals("dev_1", info!!.deviceId)
        assertEquals(EnrollmentState.ENROLLED, info.state)

        val identity = store.openIdentity()
        assertNotNull(identity)
        identity!!.use {
            assertEquals("dev_1", it.deviceId)
            assertArrayEquals(credential.toByteArray(), it.credentialForTransport())
            assertArrayEquals(privateKey, it.identityPrivateKeyForTransport())
            assertArrayEquals(publicKey, it.identityPublicKey)
        }
    }

    @Test
    fun `closing the identity zeroes the decrypted secrets`() = runTest {
        store.enroll(request())
        val identity = store.openIdentity()!!
        val credentialBytes = identity.credentialForTransport()
        val keyBytes = identity.identityPrivateKeyForTransport()

        identity.close()

        assertArrayEquals(ByteArray(credentialBytes.size), credentialBytes)
        assertArrayEquals(ByteArray(keyBytes.size), keyBytes)
    }

    @Test
    fun `nothing secret is stored in plaintext on disk`() = runTest {
        store.enroll(request())

        val raw = enrollmentFileContents()
        assertFalse("the credential must never be written in the clear", raw.contains(credential))
        assertFalse(
            "the identity private key must never be written in the clear",
            raw.contains(Base64.getEncoder().encodeToString(privateKey)) ||
                raw.contains(privateKey.joinToString("") { "%02x".format(it) }),
        )
        assertEquals("both the credential and the private key must be sealed", 2, cipher.sealCount)
    }

    @Test
    fun `clear removes the enrollment and every stored secret`() = runTest {
        store.enroll(request())

        assertTrue(store.clear(ClearReason.REVOKED))

        assertNull(store.info())
        assertNull(store.openIdentity())
        assertEquals(ClearReason.REVOKED, store.lastClearReason())
        val raw = enrollmentFileContents()
        assertFalse("the sealed record must be gone", raw.contains("credential"))
        assertFalse("the sealed key must be gone", raw.contains("identity_private_key"))
    }

    @Test
    fun `an unreadable blob degrades to unenrolled and is discarded`() = runTest {
        store.enroll(request())

        cipher.failOpens = true

        assertNull("an undecryptable enrollment must not be presented", store.openIdentity())
        assertNull("the status must not claim a usable enrollment", store.info())
        assertEquals(
            "unreadable material must be discarded rather than kept",
            ClearReason.UNREADABLE,
            store.lastClearReason(),
        )
    }

    @Test
    fun `enrollment is refused when it cannot be sealed`() = runTest {
        cipher.failSeals = true

        val error = runCatching { store.enroll(request()) }.exceptionOrNull()

        assertTrue("sealing failure must be explicit, got $error", error is EnrollmentStorageException)
        assertNull("a failed seal must not persist a half enrollment", store.info())
    }

    @Test
    fun `the store contract exposes no plaintext secret getter`() {
        val source = File("src/main/java/com/phoneconnect/agent/EnrollmentStore.kt").readText()
        val contract = source.substringAfter("interface EnrollmentStore").substringBefore("\n}")

        assertFalse("the store must not hand out a credential string", contract.contains(": String"))
        assertFalse("the store must not hand out raw key bytes", contract.contains(": ByteArray"))
    }

    @Test
    fun `general agent code never decrypts device secrets`() {
        val mainSources = File("src/main/java")
            .walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .associate { it.name to it.readText() }

        assertEquals(
            "the boundary marker must be declared once",
            setOf("EnrollmentStore.kt"),
            mainSources.filterValues { it.contains("annotation class IdentityBoundary") }.keys,
        )
        assertEquals(
            "only the enrollment storage implementation may opt in",
            setOf("KeystoreEnrollmentStore.kt"),
            mainSources.filterValues { it.contains("@OptIn(IdentityBoundary::class)") }.keys,
        )

        val decryptCallers = mainSources.filterValues { it.contains("openIdentity(") }.keys
        assertEquals(
            "only the boundary's declaration and its storage may open an identity",
            setOf("EnrollmentStore.kt", "KeystoreEnrollmentStore.kt"),
            decryptCallers,
        )
    }

    @Test
    fun `the production cipher is bound to the Android keystore`() {
        val source = File("src/main/java/com/phoneconnect/agent/KeystoreSecretCipher.kt").readText()

        assertTrue(source.contains("AndroidKeyStore"))
        assertTrue(source.contains("AES/GCM/NoPadding"))
        assertTrue("the keystore key must be non-exportable", source.contains("setUserAuthenticationRequired(false)"))
        assertTrue("GCM IVs must be random per write", source.contains("setRandomizedEncryptionRequired(true)"))
    }

    private fun request() = EnrollmentRequest(
        deviceId = "dev_1",
        credential = credential,
        identityPrivateKey = privateKey.copyOf(),
        identityPublicKey = publicKey.copyOf(),
        enrolledAtMs = 1_000L,
    )

    private fun enrollmentFileContents(): String {
        val prefsDir = File(context.dataDir, "shared_prefs")
        val file = File(prefsDir, "${KeystoreEnrollmentStore.PREFERENCES_NAME}.xml")
        if (file.isFile) {
            return file.readText()
        }
        return context.getSharedPreferences(KeystoreEnrollmentStore.PREFERENCES_NAME, Context.MODE_PRIVATE)
            .all
            .values
            .joinToString("\n")
    }

    private class FakeSecretCipher : SecretCipher {
        var sealCount = 0
            private set
        var failOpens = false
        var failSeals = false

        override fun seal(plaintext: ByteArray): ByteArray {
            if (failSeals) throw EncryptionException("keystore unavailable")
            sealCount += 1
            return byteArrayOf(0xA5.toByte(), 0x5A.toByte()) + plaintext.reversedArray()
        }

        override fun open(ciphertext: ByteArray): ByteArray {
            if (failOpens) throw EncryptionException("key invalidated")
            require(ciphertext.size >= 2 && ciphertext[0] == 0xA5.toByte() && ciphertext[1] == 0x5A.toByte())
            return ciphertext.copyOfRange(2, ciphertext.size).reversedArray()
        }
    }
}
