package uk.gov.dwp.dataworks.decryption

import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.S3Object
import com.amazonaws.services.s3.model.S3ObjectSummary
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.apache.spark.api.java.JavaSparkContext
import org.apache.spark.SparkConf

object DKSDecryption {
    private val logger: Logger = LoggerFactory.getLogger(DKSDecryption::class.toString())

    @JvmStatic
    fun main(args: Array<String>) {
        logger.info("startinggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")
        //val spark = SparkSession.builder().appName("Simple Application").getOrCreate()
        val conf = SparkConf().setAppName("Simple Application")
        val sc = JavaSparkContext(conf)
        val s3Client = S3Client.amazonS3()
        val summaries: List<S3ObjectSummary> =  s3Client.listObjectsV2("7586991bcd4c4ab28d818838a93fcc90", "dks-test-1").objectSummaries
        sc.sparkContext().parallelize(summaries)
        println("summaries "+summaries)
        //val keyValueMap  = summaries.map { s3Client.getObjectMetadata("bucket",it.key) to  s3Client.getObject("bucket",it.key) }.toMap()
        //val decrypted = keyValueMap.map { (k, v ) ->  decrypt(k, v)}
        //val logData = spark.read().textFile(args[0]).cache()
        // get the names of the files
        // get the metadata for the s3 file passed
        //
        //spark.stop()
    }

    fun decrypt(metadata: ObjectMetadata, content: S3Object){

        val iv = metadata.userMetadata["iv"]
        val cipherText = metadata.userMetadata["cipherText"]
    }
}
