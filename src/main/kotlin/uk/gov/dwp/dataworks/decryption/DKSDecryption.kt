package uk.gov.dwp.dataworks.decryption

import app.services.impl.AESCipherService
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.S3Object
import com.amazonaws.services.s3.model.S3ObjectSummary
import org.apache.spark.SparkConf
import org.apache.spark.api.java.JavaSparkContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.gov.dwp.dataworks.dks.client.DKSClient
import uk.gov.dwp.dataworks.s3.S3Client

object DKSDecryption {
    private val logger: Logger = LoggerFactory.getLogger(DKSDecryption::class.toString())
    private const val IV = "iv"
    private const val CIPHERTEXT = "cipherText"
    private const val DATAKEYENCRYPTIONID = "datakeyencryptionkeyid"

    @JvmStatic
    fun main(args: Array<String>) {
        val bucketName = args[0]
        val prefix = args[1]
        val region = args[2]
        logger.info("Starting spark job to read from the Bucket: $bucketName in the region $region with the prefix $prefix")
        val sc = getSparkContext()
        val s3Client = getS3Client(region)
        val summaries: List<S3ObjectSummary> = s3Client.listObjectsV2(bucketName, prefix).objectSummaries
        val rdd = sc.parallelize(summaries).map { it.key }.mapPartitions {
            val objectSummaries = mutableListOf<String>()
            while (it.hasNext()) {
                val key = it.next()
                val s3ClientInExecutor = S3Client.amazonS3(region)
                val metadata = s3ClientInExecutor.getObjectMetadata(bucketName, key)
                val s3Object = s3ClientInExecutor.getObject(bucketName, key)
                objectSummaries.add(decrypt(metadata, s3Object))
            }
            objectSummaries.iterator()
        }
        val decrypted = rdd.map { it.split("\n") }
        logger.info("decrypted top 2 " + decrypted.take(2))
    }

    private fun getS3Client(region: String): AmazonS3 {
        return  S3Client.amazonS3(region)
    }

    fun getSparkContext(): JavaSparkContext {
        val conf = SparkConf().setAppName("s3-data-decryption")
        val sc = JavaSparkContext(conf)
        return sc
    }

    private fun decrypt(metadata: ObjectMetadata, s3Object: S3Object): String {

        val iv = metadata.userMetadata[IV]
        val cipherText = metadata.userMetadata[CIPHERTEXT]
        val datakeyEncryptionkeyId = metadata.userMetadata[DATAKEYENCRYPTIONID]
        val content = s3Object.objectContent
        val key = s3Object.key
        logger.info("Metadata for the key $key :: iv: $iv cipherText: $cipherText dataencryptionkeid: $datakeyEncryptionkeyId")

        logger.debug("Calling DKS to decrypt key")
        val decryptedKey = DKSClient.decryptKey(datakeyEncryptionkeyId!!, cipherText!!)
        logger.debug("DKS decrypted key successfully!")

        return AESCipherService.decrypt(decryptedKey, iv!!, content)
    }
}
