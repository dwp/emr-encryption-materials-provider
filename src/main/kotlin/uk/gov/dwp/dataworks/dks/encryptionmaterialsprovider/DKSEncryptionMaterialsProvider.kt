package uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider

import com.amazonaws.services.s3.model.EncryptionMaterials
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.apache.hadoop.conf.Configurable
import org.apache.hadoop.conf.Configuration
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.dwp.dataworks.dks.providers.impl.SecureHttpClientProvider
import uk.gov.dwp.dataworks.dks.services.KeyService
import uk.gov.dwp.dataworks.dks.services.impl.HttpKeyService
import java.io.FileInputStream
import java.util.*
import javax.crypto.spec.SecretKeySpec

/**
 * Class to provide encryption materials to an EMR cluster using DKS.
 */
class DKSEncryptionMaterialsProvider : EncryptionMaterialsProvider, Configurable {

    private val IDENTITY_KEYSTORE = "identity.keystore"
    private val IDENTITY_STORE_PWD = "identity.store.password"
    private val IDENTITY_STORE_ALIAS = "identity.store.alias"
    private val IDENTITY_KEY_PASSWORD = "identity.key.password"
    private val TRUST_KEYSTORE = "trust.keystore"
    private val TRUST_STORE_PASSWORD = "trust.store.password"
    private val ALGORITHM = "AES"
    private val METADATA_KEYID = "keyid"
    private val METADATA_ENCRYPTED_KEY = "encryptedkey"

    private val DATA_KEY_SERVICE_URL = "data.key.service.url"

    private val DKS_PROPERTIES_PATH = "/opt/emr/dks.properties"
    private lateinit var keyService: KeyService

    private lateinit var configuration: Configuration

    override fun getConf(): Configuration {
        return this.configuration
    }

    override fun setConf(conf: Configuration) {
        this.configuration = conf
        logger.debug("Configuration received: $conf")
        val keyService = init()
        initializeKeyservice(keyService)
    }

    private fun init(): KeyService {
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

        return HttpKeyService(httpClientProvider, dataKeyServiceUrl)
    }

    fun initializeKeyservice(keyService: KeyService) {
        this.keyService = keyService
    }

    override fun refresh() {}

    override fun getEncryptionMaterials(): EncryptionMaterials {
        throw UnsupportedOperationException("Secret Key pair is not initialised.")
    }

    override fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>): EncryptionMaterials {
        val materialsDescriptionStr = materialsDescription.entries.joinToString("\n") { "$it.key : ${it.value}" }
        logger.debug("Received materials description $materialsDescriptionStr")
        val keyId = materialsDescription[METADATA_KEYID]
        val encryptedKey = materialsDescription[METADATA_ENCRYPTED_KEY]
        logger.info("Received keyId: '$keyId' and encryptedKey: '$encryptedKey' from materials description")
        return if (null == keyId && null == encryptedKey) {
            getMaterialForEncryption()
        } else {
            getMaterialForDecryption(keyId, encryptedKey)
        }
    }

    private fun getMaterialForEncryption(): EncryptionMaterials {
        logger.debug("Calling DKS to generate key")
        val dataKeyResult = keyService.batchDataKey()
        val decodeKey = Base64.getDecoder().decode(dataKeyResult.plaintextDataKey)
        val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, ALGORITHM)
        logger.debug("DKS generated key successfully!")
        val keyId = dataKeyResult.dataKeyEncryptionKeyId
        val cipherKey = dataKeyResult.ciphertextDataKey
        logger.info("Adding key id '$keyId' and cipher key '$cipherKey' to the S3 metadata")
        return EncryptionMaterials(secretKeySpec)
            .addDescription(METADATA_KEYID, keyId)
            .addDescription(METADATA_ENCRYPTED_KEY, cipherKey)
    }

    private fun getMaterialForDecryption(keyId: String?, encryptedKey: String?): EncryptionMaterials {
        logger.debug("Calling DKS to decrypt key")
        val decryptedKey = keyService.decryptKey(keyId!!, encryptedKey!!)
        val decodeKey = Base64.getDecoder().decode(decryptedKey)
        val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, ALGORITHM)
        logger.debug("DKS decrypted key successfully!")
        return EncryptionMaterials(secretKeySpec)
    }

    private fun getDKSProperties(): Map<String, String> {
        val prop = Properties()
        try {
            val inputStream = FileInputStream(DKS_PROPERTIES_PATH)
            prop.load(inputStream)
        } catch (e: Exception) {
            logger.error("Exception when loading DKS properties", e)
            throw e
        }
        return prop.entries.map { it.key as String to it.value as String }.toMap()
    }

    private fun validateDKSProperty(property: String?): String {
        if (property.isNullOrBlank()) throw IllegalArgumentException("$property cannot be null or blank")
        return property
    }

    companion object {
        val logger: Logger = LoggerFactory.getLogger(DKSEncryptionMaterialsProvider::class.toString())
    }
}
