package uk.gov.dwp.dataworks.dks.services.impl

import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.gson.Gson
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.ContentType
import org.apache.http.entity.StringEntity
import org.apache.http.util.EntityUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.dwp.dataworks.dks.domain.DataKeyResult
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyDecryptionException
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyServiceUnavailableException
import uk.gov.dwp.dataworks.dks.providers.HttpClientProvider
import uk.gov.dwp.dataworks.dks.services.KeyService
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

open class HttpKeyService(private val httpClientProvider: HttpClientProvider, val dataKeyServiceUrl: String) : KeyService {

    companion object {
        val logger: Logger = LoggerFactory.getLogger(HttpKeyService::class.toString())
    }

    override fun batchDataKey(): DataKeyResult {
        try {
            val dksUrl = "$dataKeyServiceUrl/datakey"
            logger.info("dataKeyServiceUrl: '$dksUrl'.")
            httpClientProvider.client().use { client ->
                client.execute(HttpGet(dksUrl)).use { response ->
                    val statusCode = response.statusLine.statusCode
                    logger.info("dataKeyServiceUrl: '$dksUrl' returned status code '$statusCode'.")
                    return if (statusCode == 201) {
                        val entity = response.entity
                        val result = BufferedReader(InputStreamReader(entity.content))
                            .use(BufferedReader::readText).let {
                                Gson().fromJson(it, DataKeyResult::class.java)
                            }
                        EntityUtils.consume(entity)
                        result
                    }
                    else {
                        throw DataKeyServiceUnavailableException("data key service returned status code '$statusCode'.")
                    }
                }
            }
        }
        catch (ex: Exception) {
            when (ex) {
                is DataKeyServiceUnavailableException -> {
                    throw ex
                }
                else -> throw DataKeyServiceUnavailableException("Error contacting data key service: $ex")
            }
        }
    }

    override fun decryptKey(encryptionKeyId: String, encryptedKey: String): String {
        logger.info("Decrypting encryptedKey: '$encryptedKey', keyEncryptionKeyId: '$encryptionKeyId'.")
        try {
            val cacheKey = "$encryptedKey/$encryptionKeyId"
            if (decryptedKeyCache.getIfPresent(cacheKey) != null) {
                return decryptedKeyCache.getIfPresent(cacheKey)!!
            }
            else {
                httpClientProvider.client().use { client ->
                    val dksUrl = """$dataKeyServiceUrl/datakey/actions/decrypt?keyId=${URLEncoder.encode(encryptionKeyId, "US-ASCII")}"""
                    logger.info("Calling dataKeyServiceUrl: '$dksUrl'.")
                    val httpPost = HttpPost(dksUrl)
                    httpPost.entity = StringEntity(encryptedKey, ContentType.TEXT_PLAIN)
                    client.execute(httpPost).use { response ->
                        val statusCode = response.statusLine.statusCode
                        logger.info("dataKeyServiceUrl: '$dksUrl' returned status code '$statusCode'.")
                        return when (statusCode) {
                            200 -> {
                                val entity = response.entity
                                val text = BufferedReader(InputStreamReader(response.entity.content)).use(BufferedReader::readText)
                                EntityUtils.consume(entity)
                                val dataKeyResult = Gson().fromJson(text, DataKeyResult::class.java)
                                decryptedKeyCache.put(cacheKey, dataKeyResult.plaintextDataKey)
                                dataKeyResult.plaintextDataKey
                            }
                            400 ->
                                throw DataKeyDecryptionException(
                                    "Decrypting encryptedKey: '$encryptedKey' with keyEncryptionKeyId: '$encryptionKeyId' data key service returned status code '$statusCode'")
                            else ->
                                throw DataKeyServiceUnavailableException(
                                    "Decrypting encryptedKey: '$encryptedKey' with keyEncryptionKeyId: '$encryptionKeyId' data key service returned status code '$statusCode'")
                        }
                    }
                }
            }
        }
        catch (ex: Exception) {
            when (ex) {
                is DataKeyDecryptionException, is DataKeyServiceUnavailableException -> {
                    throw ex
                }
                else -> throw DataKeyServiceUnavailableException("Error contacting data key service: $ex")
            }
        }
    }

    fun clearCache() {
        decryptedKeyCache.invalidateAll()
    }

    val decryptedKeyCache: Cache<String, String> = CacheBuilder.newBuilder()
        .expireAfterWrite(86400, TimeUnit.SECONDS)
        .build()

}
