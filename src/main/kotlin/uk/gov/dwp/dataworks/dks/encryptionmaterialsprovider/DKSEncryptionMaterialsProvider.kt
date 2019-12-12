package uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider

import com.amazonaws.services.s3.model.EncryptionMaterials
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.apache.hadoop.conf.Configurable
import org.apache.hadoop.conf.Configuration
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

    private lateinit var keyService: KeyService

    private lateinit var configuration: Configuration

    override fun getConf(): Configuration {
        return this.configuration
    }

    override fun setConf(conf: Configuration) {
        this.configuration = conf
    }

    init {
        initializeKeyService()
    }

    private fun initializeKeyService() {
        val values = getProperty()
        println("Values: $values")
        val identityStore = values["identity.keystore"]
        val identityStorePassword = values["identity.store.password"]
        val identityStoreAlias = values["identity.store.alias"]
        val identityKeyPassword = values["identity.key.password"]
        val trustStore = values["trust.keystore"]
        val trustStorePassword = values["trust.store.password"]
        val dataKeyServiceUrl = values["data.key.service.url"]

        val httpClientProvider = SecureHttpClientProvider(identityStore!!, identityStorePassword!!, identityStoreAlias!!, identityKeyPassword!!,
            trustStore!!, trustStorePassword!!)

        keyService = HttpKeyService(httpClientProvider, dataKeyServiceUrl!!)
    }

    override fun refresh() {}

    override fun getEncryptionMaterials(): EncryptionMaterials {
        val dataKeyResult =  keyService.batchDataKey()
        val decodeKey = Base64.getDecoder().decode(dataKeyResult.plaintextDataKey)
        val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, "AES")
        println("secretKeySpecPub: $secretKeySpec")
        return EncryptionMaterials(secretKeySpec)
            .addDescription("keyid",dataKeyResult.dataKeyEncryptionKeyId)
            .addDescription("encryptedKey",dataKeyResult.ciphertextDataKey)
    }

    override fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>?): EncryptionMaterials {
        val keyId = materialsDescription?.get("keyid")
        val encryptedDataKey = materialsDescription?.get("encryptedKey")
        if(null == keyId && null == encryptedDataKey){
            val dataKeyResult =  keyService.batchDataKey()
            println("key ${dataKeyResult.plaintextDataKey}")
            println("id ${dataKeyResult.dataKeyEncryptionKeyId}")
            println("ckey ${dataKeyResult.ciphertextDataKey}")

            val decodeKey = Base64.getDecoder().decode(dataKeyResult.plaintextDataKey)
            val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, "AES")
            println("secretKeySpec: $secretKeySpec")
            val encryptionmaterials =  EncryptionMaterials(secretKeySpec)
                .addDescription("keyid",dataKeyResult.dataKeyEncryptionKeyId)
                .addDescription("encryptedKey",dataKeyResult.ciphertextDataKey)
            println("encryptionmaterials: $encryptionmaterials")

            return encryptionMaterials

        }
        else {
            val decryptedKey = keyService.decryptKey(keyId!!, encryptedDataKey!!)
            val decodeKey = Base64.getDecoder().decode(decryptedKey)
            val secretKeySpec = SecretKeySpec(decodeKey, 0, decodeKey.size, "AES")
            return EncryptionMaterials(secretKeySpec)
        }
    }

    fun getProperty(): Map<String, String> {
        val prop = Properties()
        val map = HashMap<String, String>()
        try {
            val inputStream = FileInputStream("/opt/emr/dks.properties")
            prop.load(inputStream)
        }
        catch (e: Exception) {
            e.printStackTrace()
            println("Some issue finding or loading file....!!! " + e.message)

        }
        for (entry in prop.entries) {
            map[entry.key as String] = entry.value as String
        }
        return map
    }
}
