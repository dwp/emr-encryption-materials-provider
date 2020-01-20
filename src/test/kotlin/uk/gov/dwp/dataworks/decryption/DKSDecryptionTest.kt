package uk.gov.dwp.dataworks.decryption

import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.S3Object
import com.amazonaws.services.s3.model.S3ObjectInputStream
import com.amazonaws.services.s3.model.S3ObjectSummary
import io.mockk.every
import io.mockk.mockk
import io.mockk.spyk
import org.junit.jupiter.api.Test
import uk.gov.dwp.dataworks.dks.client.DKSClient


class DKSDecryptionTest {

    @Test
    fun testMain(){
        val array = arrayOf("bucket", "prefix", "eu-west-2")
       // val conf = SparkConf().setAppName("s3-data-decryption-test").setMaster("local")
       // val localSparkContext =  JavaSparkContext(conf)
        val dksDecryption = spyk(DKSDecryption)
        val mockS3Client : AmazonS3 = mockk()
        val objectSummary1 = S3ObjectSummary()
        objectSummary1.key = "key1"
        val objectSummary2 = S3ObjectSummary()
        objectSummary2.key = "key2"

        val objectMetadata1 = ObjectMetadata()
        objectMetadata1.userMetadata.put("iv", "iv")
        objectMetadata1.userMetadata.put("cipherText", "cipherText")
        objectMetadata1.userMetadata.put("datakeyencryptionkeyid", "datakeyencryptionkeyid")

        val objectMetadata2 = ObjectMetadata()
        objectMetadata2.userMetadata.put("iv", "iv")
        objectMetadata2.userMetadata.put("cipherText", "cipherText")
        objectMetadata2.userMetadata.put("datakeyencryptionkeyid", "datakeyencryptionkeyid")

        val s3Object1 = S3Object()
        s3Object1.bucketName = array[0]
        s3Object1.key = "key1"
        s3Object1.objectContent =  S3ObjectInputStream("sampleText1".toByteArray().inputStream(), null)

        val s3Object2 = S3Object()
        s3Object2.bucketName = array[0]
        s3Object2.key = "key2"
        s3Object2.objectContent = S3ObjectInputStream("sampleText2".toByteArray().inputStream(), null)



        val summaries = mutableListOf<S3ObjectSummary>()
        summaries.add(objectSummary1)
        summaries.add(objectSummary2)

        val mockDKSClient: DKSClient = mockk()


        every { mockS3Client.listObjectsV2(array[0], array[1]).objectSummaries } returns summaries

        every { dksDecryption.getS3Client(array[2]) } returns  mockS3Client
        every { dksDecryption.getS3Client(array[2]) } returns  mockS3Client
        every { mockS3Client.getObjectMetadata(array[0], "key1") } returns objectMetadata1
        every { mockS3Client.getObjectMetadata(array[0], "key2") } returns objectMetadata2

        every { mockS3Client.getObject(array[0], "key1") } returns s3Object1
        every { mockS3Client.getObject(array[0], "key2") } returns s3Object2

        every { dksDecryption.getDKSClient() } returns mockDKSClient
        every { mockDKSClient.decryptKey("", "") } returns ""

       // every { dksDecryption.getSparkContext() } returns localSparkContext
        dksDecryption.main(array)

    }
}
