package uk.gov.dwp.dataworks.dks.providers.impl

import org.apache.http.client.config.RequestConfig
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContexts
import uk.gov.dwp.dataworks.dks.providers.HttpClientProvider
import uk.gov.dwp.dataworks.utility.PropertyUtility.property
import java.io.File
import javax.net.ssl.SSLContext

open class SecureHttpClientProvider(val identityStore: String, val identityStorePassword: String, val identityStoreAlias: String,
                                    val identityKeyPassword: String, val trustStore: String, val trustStorePassword: String) : HttpClientProvider {


    override fun client(): CloseableHttpClient =
        HttpClients.custom().run {
            setDefaultRequestConfig(requestConfig())
            setSSLSocketFactory(connectionFactory())
            build()
        }


    private fun requestConfig(): RequestConfig =
        RequestConfig.custom().run {
            setSocketTimeout(property(SOCKET_TIMEOUT_PROPERTY_NAME, "300000").toInt())
            setConnectTimeout(property(CONNECT_TIMEOUT_PROPERTY_NAME, "300000").toInt())
            setConnectionRequestTimeout(property(CONNECTION_REQUEST_TIMEOUT_PROPERTY_NAME, "300000").toInt())
            build()
        }


    private fun connectionFactory() = SSLConnectionSocketFactory(
        sslContext(),
        arrayOf("TLSv1.2"),
        null,
        SSLConnectionSocketFactory.getDefaultHostnameVerifier())

    private fun sslContext(): SSLContext =
        SSLContexts.custom().run {
            loadKeyMaterial(
                File(identityStore),
                identityStorePassword.toCharArray(),
                identityKeyPassword.toCharArray()) { _, _ -> identityStoreAlias }
            loadTrustMaterial(File(trustStore), trustStorePassword.toCharArray())
            build()
        }

    companion object {
        private const val SOCKET_TIMEOUT_PROPERTY_NAME = "socket.timeout"
        private const val CONNECT_TIMEOUT_PROPERTY_NAME = "connect.timeout"
        private const val CONNECTION_REQUEST_TIMEOUT_PROPERTY_NAME = "connection.request.timeout"
    }
}
