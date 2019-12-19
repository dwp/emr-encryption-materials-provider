package uk.gov.dwp.dataworks.encryptionmaterialsprovider

import com.amazonaws.regions.Regions
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import com.amazonaws.services.s3.model.EncryptionMaterials
import com.amazonaws.services.s3.model.EncryptionMaterialsProvider
import org.apache.hadoop.conf.Configurable
import org.apache.hadoop.conf.Configuration

/**
 * Class to provide encryption materials to an EMR cluster using RSA key pair stored in S3 buckets.
 */
@Deprecated("Superseded by uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider.DKSEncryptionMaterialsProvider")
class DWEncryptionMaterialsProvider : EncryptionMaterialsProvider, Configurable {

    lateinit var configuration: Configuration
    private lateinit var materialsResolver: MaterialsResolver
    private val s3: AmazonS3 = AmazonS3ClientBuilder.standard()
        .withRegion(Regions.EU_WEST_2)
        .build()

    override fun getConf(): Configuration {
        return this.configuration
    }

    override fun setConf(conf: Configuration) {
        this.configuration = conf
        materialsResolver = MaterialsResolver(conf, s3, 86400L)
    }

    override fun refresh() {}

    override fun getEncryptionMaterials(): EncryptionMaterials {
        throw UnsupportedOperationException("RSA Key pair is not initialised.")
    }

    override fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>?): EncryptionMaterials {
        check(materialsDescription != null) { "Cannot handle materialsDescription as it is null" }
        return materialsResolver.getEncryptionMaterials(materialsDescription as MutableMap<String, String?>)
    }
}
