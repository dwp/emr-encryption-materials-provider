package uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider

import com.amazonaws.services.s3.model.EncryptionMaterials
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.apache.hadoop.conf.Configurable
import org.apache.hadoop.conf.Configuration
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import uk.gov.dwp.dataworks.dks.services.KeyService
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Class to provide encryption materials to an EMR cluster using DKS.
 */
@Component
class DKSEncryptionMaterialsProvider : EncryptionMaterialsProvider, Configurable {

    @Autowired
    private lateinit var keyService:KeyService

    private val keyFactory = java.security.KeyFactory.getInstance("RSA")

    private lateinit var configuration: Configuration

    override fun getConf(): Configuration {
        return this.configuration
    }

    override fun setConf(conf: Configuration) {
        this.configuration = conf
    }

    override fun refresh() {}

    override fun getEncryptionMaterials(): EncryptionMaterials {
        val dataKeyResult =  keyService.batchDataKey()
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(dataKeyResult.plaintextDataKey.toByteArray()))
        val keyPair = KeyPair(publicKey,null)
        return EncryptionMaterials(keyPair)
            .addDescription("keyid",dataKeyResult.dataKeyEncryptionKeyId)
            .addDescription("encryptedKey",dataKeyResult.ciphertextDataKey)
    }

    override fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>?): EncryptionMaterials {
        val keyId = materialsDescription?.get("keyid")
        val encryptedDataKey = materialsDescription?.get("encryptedKey")
        val privateKey = keyService.decryptKey(keyId!!, encryptedDataKey!!)
        val symmetricKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKey.toByteArray()))
        val keyPair = KeyPair(null,symmetricKey)
        return EncryptionMaterials(keyPair)
    }
}
