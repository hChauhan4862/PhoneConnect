package com.phoneconnect.agent

import com.phoneconnect.agent.crypto.IdentityKey
import com.phoneconnect.agent.net.HubClient

/**
 * One enrollment: generate the device identity, exchange the one-time token for a device
 * credential, and persist both sealed.
 *
 * This is part of the identity boundary on purpose. The setup screen calls it and never
 * touches a private key or a credential itself, which is what keeps
 * [EnrollmentStore.openIdentity] out of general agent code.
 */
@OptIn(IdentityBoundary::class)
class EnrollmentFlow(
    private val store: EnrollmentStore,
    private val hub: HubClient,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    suspend fun enroll(token: String): Result<EnrollmentInfo> = runCatching {
        val identity = IdentityKey.generate()
        try {
            val enrolled = hub.enroll(token, identity.publicKeyBase64Url()).getOrThrow()
            store.enroll(
                EnrollmentRequest(
                    deviceId = enrolled.deviceId,
                    credential = enrolled.credential,
                    identityPrivateKey = identity.secretBytes(),
                    identityPublicKey = identity.publicKey(),
                    enrolledAtMs = clock(),
                ),
            )
            EnrollmentInfo(enrolled.deviceId, EnrollmentState.ENROLLED, clock())
        } finally {
            identity.close()
        }
    }
}
