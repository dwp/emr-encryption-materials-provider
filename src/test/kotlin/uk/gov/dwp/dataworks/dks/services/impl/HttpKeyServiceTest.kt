package uk.gov.dwp.dataworks.dks.services.impl

import com.google.gson.Gson
import org.apache.http.HttpEntity
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.impl.client.CloseableHttpClient
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.ArgumentMatchers.any
import org.mockito.BDDMockito.given
import org.mockito.BDDMockito.then
import org.mockito.Mockito.mock
import org.mockito.Mockito.times
import uk.gov.dwp.dataworks.dks.domain.DataKeyResult
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyDecryptionException
import uk.gov.dwp.dataworks.dks.providers.HttpClientProvider
import java.io.ByteArrayInputStream

class HttpKeyServiceTest {

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
        val httpClientProvider = mock(HttpClientProvider::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(201)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpGet::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val keyService = HttpKeyService(httpClientProvider, "http://dummyurl.com")
        val dataKeyResult = keyService.batchDataKey()

        val expectedResult: DataKeyResult = Gson().fromJson(responseBody, DataKeyResult::class.java)
        assertEquals(expectedResult, dataKeyResult)

        then(httpClient).should(times(1)).execute(any(HttpGet::class.java))
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
        val httpClientProvider = mock(HttpClientProvider::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(200)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val keyService = HttpKeyService(httpClientProvider, "http://dummyurl.com")
        val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")

        assertEquals("PLAINTEXT_DATAKEY", dataKeyResult)
        then(httpClient).should(times(1)).execute(any(HttpPost::class.java))
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
        val httpClientProvider = mock(HttpClientProvider::class.java)
        given(entity.content).willReturn(byteArrayInputStream)
        given(statusLine.statusCode).willReturn(200)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        given(httpResponse.entity).willReturn(entity)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val keyService = HttpKeyService(httpClientProvider, "http://dummyurl.com")
        val dataKeyResult = keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
        assertEquals("PLAINTEXT_DATAKEY", dataKeyResult)

        keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
        then(httpClient).should(times(1)).execute(any(HttpPost::class.java))
    }

    @Test
    fun testDecryptKey_WithABadKey_WillCallServerOnce_AndNotRetry() {
        val statusLine = mock(StatusLine::class.java)
        val httpClientProvider = mock(HttpClientProvider::class.java)
        given(statusLine.statusCode).willReturn(400)
        val httpResponse = mock(CloseableHttpResponse::class.java)
        given(httpResponse.statusLine).willReturn(statusLine)
        val httpClient = mock(CloseableHttpClient::class.java)
        given(httpClient.execute(any(HttpPost::class.java))).willReturn(httpResponse)
        given(httpClientProvider.client()).willReturn(httpClient)

        val keyService = HttpKeyService(httpClientProvider, "http://dummyurl.com")
        assertThrows<DataKeyDecryptionException>("Decrypting encryptedKey: 'ENCRYPTED_KEY_ID' with keyEncryptionKeyId: '123' data key service returned status code '400'") {
            keyService.decryptKey("123", "ENCRYPTED_KEY_ID")
        }
        then(httpClient).should(times(1)).execute(any(HttpPost::class.java))
    }


}
