package uk.gov.dwp.dataworks.dks.client

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.dwp.dataworks.dks.providers.impl.SecureHttpClientProvider
import uk.gov.dwp.dataworks.dks.services.KeyService
import uk.gov.dwp.dataworks.dks.services.impl.HttpKeyService
import uk.gov.dwp.dataworks.utility.PropertyUtility.properties
import kotlin.time.ExperimentalTime

@ExperimentalTime
object DKSClientImpl : DKSClient {

    private val IDENTITY_KEYSTORE = "identity.keystore"
    private val IDENTITY_STORE_PWD = "identity.store.password"
    private val IDENTITY_STORE_ALIAS = "identity.store.alias"
    private val IDENTITY_KEY_PASSWORD = "identity.key.password"
    private val TRUST_KEYSTORE = "trust.keystore"
    private val TRUST_STORE_PASSWORD = "trust.store.password"
    private val DATA_KEY_SERVICE_URL = "data.key.service.url"
    private val keyService: KeyService
    private val logger: Logger = LoggerFactory.getLogger(DKSClientImpl::class.toString())

    init {
        val dksValues = properties()
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

    override fun decryptKey(encryptionKeyId: String, encryptedKey: String): String {
        return keyService.decryptKey(encryptionKeyId, encryptedKey)
    }

    private fun validateDKSProperty(property: String?): String {
        if (property.isNullOrBlank()) throw IllegalArgumentException("$property cannot be null or blank")
        return property
    }
}
