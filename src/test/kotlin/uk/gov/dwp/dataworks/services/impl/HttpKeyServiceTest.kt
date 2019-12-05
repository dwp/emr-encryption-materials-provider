package uk.gov.dwp.dataworks.services.impl

import app.services.impl.HttpKeyService
import com.google.gson.Gson
import org.apache.http.HttpEntity
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.CloseableHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers.any
import org.mockito.BDDMockito.given
import org.mockito.Mockito.*
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.context.junit4.SpringRunner
import uk.gov.dwp.dataworks.dks.domain.DataKeyResult
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyDecryptionException
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyServiceUnavailableException
import uk.gov.dwp.dataworks.dks.providers.HttpClientProvider
import java.io.ByteArrayInputStream

@RunWith(SpringRunner::class)
@ActiveProfiles( "httpDataKeyService")
@TestPropertySource(properties = [
    "data.key.service.url=dummy.com:8090",
    "identity.keystore=resources/identity.jks",
    "trust.keystore=resources/truststore.jks",
    "identity.store.password=changeit",
    "identity.key.password=changeit",
    "trust.store.password=changeit",
    "identity.store.alias=cid"
])
class HttpKeyServiceTest {

    @Autowired
    private lateinit var keyService: HttpKeyService

    @Autowired
    private lateinit var httpClientProvider: HttpClientProvider

    @Before
    fun init() {
        this.keyService.clearCache()
        reset(this.httpClientProvider)
    }

    @Test
    fun testBatchDataKey_WillCallClientOnce_AndReturnKey() {
        val responseBody = """
            |{
            |    "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
            |    "plaintextDataKey": "PLAINTEXT_DATAKEY",
            |    "ciphertextDataKey": "CIPHERTEXT_DATAKEY"
            |}
        """.trimMargin()

        val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
        val statusLine = mock(StatusLine::class.java)
        val entity = mock(HttpEntity::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(201)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpGet::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val dataKeyResult = keyService.batchDataKey()

        val expectedResult: DataKeyResult = Gson().fromJson(responseBody, DataKeyResult::class.java)
        assertEquals(expectedResult, dataKeyResult)

        verify(httpClient, times(1)).execute(any(HttpGet::class.java))
    }

    @Test
    fun testBatchDataKey_ServerError_ThrowsException_AndWillRetry() {
        val httpClient = mock(CloseableHttpClient::class.java)
        val statusLine = mock(StatusLine::class.java)
        //val entity = mock(HttpEntity::class.java)
        given(statusLine.statusCode).willReturn(503)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpClient.execute(any(HttpGet::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        try {
            keyService.batchDataKey()
            fail("Should throw a DataKeyServiceUnavailableException")
        } catch (ex: DataKeyServiceUnavailableException) {
            assertEquals("data key service returned status code '503'.", ex.message)
            verify(httpClient, times(HttpKeyService.maxAttempts)).execute(any(HttpGet::class.java))
        }
    }

    @Test
    @Throws(DataKeyServiceUnavailableException::class)
    fun testBatchDataKey_UnknownHttpError_ThrowsException_AndWillRetry() {
        val statusLine = mock(StatusLine::class.java)
        //val entity = mock(HttpEntity::class.java)
        given(statusLine.statusCode).willReturn(503)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpGet::class.java))).willThrow(RuntimeException("Boom!"))
        given(httpClientProvider.client()).willReturn(httpClient)

        try {
            keyService.batchDataKey()
            fail("Should throw a DataKeyServiceUnavailableException")
        } catch (ex: DataKeyServiceUnavailableException) {
            assertEquals("Error contacting data key service: java.lang.RuntimeException: Boom!", ex.message)
            verify(httpClient, times(HttpKeyService.maxAttempts)).execute(any(HttpGet::class.java))
        }
    }

    @Test
    @Throws(DataKeyServiceUnavailableException::class)
    fun testBatchDataKey_WhenErrorsOccur_WillRetryUntilSuccessful() {
        val responseBody = """
            |{
            |    "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
            |    "plaintextDataKey": "PLAINTEXT_DATAKEY",
            |    "ciphertextDataKey": "CIPHERTEXT_DATAKEY"
            |}
        """.trimMargin()

        val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
        val statusLine = mock(StatusLine::class.java)
        val entity = mock(HttpEntity::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(503, 503, 201)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpGet::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val dataKeyResult = keyService.batchDataKey()

        val expectedResult: DataKeyResult = Gson().fromJson(responseBody, DataKeyResult::class.java)
        assertEquals(expectedResult, dataKeyResult)

        verify(httpClient, times(3)).execute(any(HttpGet::class.java))
    }

    @Test
    fun testDecryptKey_HappyCase_CallsServerOnce_AndReturnsUnencryptedData() {
        val responseBody = """
            |{
            |  "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
            |  "plaintextDataKey": "PLAINTEXT_DATAKEY"
            |}
        """.trimMargin()

        val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
        val statusLine = mock(StatusLine::class.java)
        val entity = mock(HttpEntity::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(200)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")

        assertEquals("PLAINTEXT_DATAKEY", dataKeyResult)
        verify(httpClient, times(1)).execute(any(HttpPost::class.java))
    }

    @Test
    fun testDecryptKey_WhenErrorOccur_WillRetryUntilSuccessful() {
        val responseBody = """
            |{
            |  "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
            |  "plaintextDataKey": "PLAINTEXT_DATAKEY"
            |}
        """.trimMargin()

        val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
        val mockStatusLine = mock(StatusLine::class.java)
        val entity = mock(HttpEntity::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(mockStatusLine.statusCode).willReturn(503, 503, 200)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(mockStatusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")

        assertEquals("PLAINTEXT_DATAKEY", dataKeyResult)

        verify(httpClient, times(3)).execute(any(HttpPost::class.java))
    }

    @Test
    fun testDecryptKey_HappyCase_WillCallServerOnce_AndCacheResponse() {
        val responseBody = """
            |{
            |  "dataKeyEncryptionKeyId": "DATAKEY_ENCRYPTION_KEY_ID",
            |  "plaintextDataKey": "PLAINTEXT_DATAKEY"
            |}
        """.trimMargin()

        val byteArrayInputStream = ByteArrayInputStream(responseBody.toByteArray())
        val statusLine = mock(StatusLine::class.java)
        val entity = mock(HttpEntity::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(200)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
        assertEquals("PLAINTEXT_DATAKEY", dataKeyResult)

        keyService.decryptKey("123", "ENCRYPTED_KEY_ID")

        verify(httpClient, times(1)).execute(any(HttpPost::class.java))
    }

    @Test
    fun testDecryptKey_WithABadKey_WillCallServerOnce_AndNotRetry() {
        val statusLine = mock(StatusLine::class.java)
        given(statusLine.statusCode).willReturn(400)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        try {
            keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
            fail("Should throw a DataKeyDecryptionException")
        } catch (ex: DataKeyDecryptionException) {
            assertEquals("Decrypting encryptedKey: 'ENCRYPTED_KEY_ID' with keyEncryptionKeyId: '123' data key service returned status code '400'", ex.message)
            verify(httpClient, times(1)).execute(any(HttpPost::class.java))
        }
    }

    @Test
    fun testDecryptKey_ServerError_WillCauseRetryMaxTimes() {
        val statusLine = mock(StatusLine::class.java)
        given(statusLine.statusCode).willReturn(503)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        try {
            keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
            fail("Should throw a DataKeyServiceUnavailableException")
        } catch (ex: DataKeyServiceUnavailableException) {
            assertEquals("Decrypting encryptedKey: 'ENCRYPTED_KEY_ID' with keyEncryptionKeyId: '123' data key service returned status code '503'", ex.message)
            verify(httpClient, times(HttpKeyService.maxAttempts)).execute(any(HttpPost::class.java))
        }
    }

    @Test
    fun testDecryptKey_UnknownHttpError_WillCauseRetryMaxTimes() {

        val statusLine = mock(StatusLine::class.java)
        given(statusLine.statusCode).willReturn(503)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willThrow(RuntimeException("Boom!"))
        given(httpClientProvider.client()).willReturn(httpClient)
        try {
            keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
            fail("Should throw a DataKeyServiceUnavailableException")
        } catch (ex: DataKeyServiceUnavailableException) {
            assertEquals("Error contacting data key service: java.lang.RuntimeException: Boom!", ex.message)
            verify(httpClient, times(HttpKeyService.maxAttempts)).execute(any(HttpPost::class.java))
        }
    }
}
