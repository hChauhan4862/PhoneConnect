package com.phoneconnect.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * `HubClient` deliberately allows plain HTTP to a loopback hub, and the compose default is
 * one. targetSdk 35 denies cleartext unless the shipped network security config permits it,
 * so these tests parse the real XML instead of trusting that it says the right thing.
 */
class NetworkSecurityConfigTest {
    private val manifest = parse(File("src/main/AndroidManifest.xml"))
    private val config = parse(File("src/main/res/xml/network_security_config.xml"))

    @Test
    fun `the application applies the network security config`() {
        val application = manifest.getElementsByTagName("application").item(0) as Element
        assertEquals(
            "the manifest must reference the shipped config",
            "@xml/network_security_config",
            application.getAttribute("android:networkSecurityConfig"),
        )
    }

    @Test
    fun `cleartext is permitted for loopback only`() {
        listOf("127.0.0.1", "localhost", "::1").forEach { host ->
            assertTrue("loopback host $host must be permitted over cleartext", cleartextPermitted(host))
        }
        listOf("example.com", "phoneconnect.example", "192.168.1.10", "localhost.example.com").forEach { host ->
            assertFalse("non-loopback host $host must not be permitted over cleartext", cleartextPermitted(host))
        }
    }

    @Test
    fun `the config never broadens cleartext past loopback`() {
        val domains = config.getElementsByTagName("domain")
        val permitted = mutableListOf<String>()
        for (index in 0 until domains.length) {
            val domain = (domains.item(index) as Element).textContent.trim()
            assertFalse("a wildcard domain would cover every host", domain == "*" || domain.startsWith("*."))
            permitted.add(domain)
        }
        assertEquals(
            "cleartext may only name the three loopback literals",
            setOf("127.0.0.1", "localhost", "::1"),
            permitted.toSet(),
        )

        val base = config.getElementsByTagName("base-config").item(0) as Element
        assertEquals(
            "everything not named above must still require TLS",
            "false",
            base.getAttribute("cleartextTrafficPermitted"),
        )
    }

    private fun cleartextPermitted(host: String): Boolean {
        // A base-config applies only when no domain-config matches.
        val base = config.getElementsByTagName("base-config").item(0) as? Element
        val default = base?.getAttribute("cleartextTrafficPermitted") == "true"
        val domainConfigs = config.getElementsByTagName("domain-config")
        for (index in 0 until domainConfigs.length) {
            val domainConfig = domainConfigs.item(index) as Element
            val cleartext = domainConfig.getAttribute("cleartextTrafficPermitted") == "true"
            val domains = domainConfig.getElementsByTagName("domain")
            for (domainIndex in 0 until domains.length) {
                val domain = domains.item(domainIndex) as Element
                val name = domain.textContent.trim()
                val includeSubdomains = domain.getAttribute("includeSubdomains") == "true"
                val matches = host.equals(name, ignoreCase = true) ||
                    (includeSubdomains && host.endsWith(".$name", ignoreCase = true))
                if (matches) {
                    return cleartext
                }
            }
        }
        return default
    }

    private fun parse(file: File): Document {
        assertTrue("${file.path} must exist", file.isFile)
        return DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
    }
}
