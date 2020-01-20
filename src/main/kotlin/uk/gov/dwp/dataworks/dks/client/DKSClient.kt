package uk.gov.dwp.dataworks.dks.client

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider.DKSEncryptionMaterialsProvider
import uk.gov.dwp.dataworks.dks.providers.impl.SecureHttpClientProvider
import uk.gov.dwp.dataworks.dks.services.KeyService
import uk.gov.dwp.dataworks.dks.services.impl.HttpKeyService
import java.io.FileInputStream
import java.util.*

object DKSClient {

    private val IDENTITY_KEYSTORE = "identity.keystore"
    private val IDENTITY_STORE_PWD = "identity.store.password"
    private val IDENTITY_STORE_ALIAS = "identity.store.alias"
    private val IDENTITY_KEY_PASSWORD = "identity.key.password"
    private val TRUST_KEYSTORE = "trust.keystore"
    private val TRUST_STORE_PASSWORD = "trust.store.password"
    private val DATA_KEY_SERVICE_URL = "data.key.service.url"
    private val DKS_PROPERTIES_PATH = "/opt/emr/dks.properties"
    private val keyService: KeyService
    private val logger: Logger = LoggerFactory.getLogger(DKSClient::class.toString())

    init {
        val dksValues = getDKSProperties()
        val identityStore = validateDKSProperty(dksValues[IDENTITY_KEYSTORE])
        val identityStorePassword = validateDKSProperty(dksValues[IDENTITY_STORE_PWD])
        val identityStoreAlias = validateDKSProperty(dksValues[IDENTITY_STORE_ALIAS])
        val identityKeyPassword = validateDKSProperty(dksValues[IDENTITY_KEY_PASSWORD])
        val trustStore = validateDKSProperty(dksValues[TRUST_KEYSTORE])
        val trustStorePassword = validateDKSProperty(dksValues[TRUST_STORE_PASSWORD])
        val dataKeyServiceUrl = validateDKSProperty(dksValues[DATA_KEY_SERVICE_URL])
        logger.debug("DKS values: Identity store path '$identityStore', Trust store path '$trustStore', DKS url '$dataKeyServiceUrl'")
        val httpClientProvider = SecureHttpClientProvider(identityStore, identityStorePassword, identityStoreAlias, identityKeyPassword,
            trustStore, trustStorePassword)
        this.keyService = HttpKeyService(httpClientProvider, dataKeyServiceUrl)
    }

    fun decryptKey(encryptionKeyId: String, encryptedKey: String): String {
        return keyService.decryptKey(encryptionKeyId, encryptedKey)
    }

    private fun getDKSProperties(): Map<String, String> {
        val prop = Properties()
        try {
            val inputStream = FileInputStream(DKS_PROPERTIES_PATH)
            prop.load(inputStream)
        }
        catch (e: Exception) {
            DKSEncryptionMaterialsProvider.logger.error("Exception when loading DKS properties", e)
            throw e
        }
        return prop.entries.map { it.key as String to it.value as String }.toMap()
    }

    private fun validateDKSProperty(property: String?): String {
        if (property.isNullOrBlank()) throw IllegalArgumentException("$property cannot be null or blank")
        return property
    }
}
