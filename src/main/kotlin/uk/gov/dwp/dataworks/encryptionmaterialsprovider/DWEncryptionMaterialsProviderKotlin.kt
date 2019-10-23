package uk.gov.dwp.dataworks.encryptionmaterialsprovider

import com.amazonaws.services.s3.model.EncryptionMaterials
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.apache.hadoop.conf.Configurable
import org.apache.hadoop.conf.Configuration

class DWEncryptionMaterialsProviderKotlin : EncryptionMaterialsProvider, Configurable {

    private lateinit var configuration: Configuration
    private lateinit var materialsResolver: MaterialsResolver

    override fun getConf(): Configuration {
        return this.configuration
    }

    override fun setConf(conf: Configuration) {
        this.configuration = conf
        materialsResolver = MaterialsResolver(conf)
    }

    override fun refresh() {}

    override fun getEncryptionMaterials(): EncryptionMaterials {
        throw UnsupportedOperationException("RSA Key pair is not initialised.")
    }

    override fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>?): EncryptionMaterials {
        return materialsResolver.getEncryptionMaterials(materialsDescription)
    }
}