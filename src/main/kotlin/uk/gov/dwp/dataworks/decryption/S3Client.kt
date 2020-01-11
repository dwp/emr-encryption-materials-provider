package uk.gov.dwp.dataworks.decryption

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain
import com.amazonaws.regions.Regions
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.AmazonS3ClientBuilder

object S3Client {

    fun amazonS3(): AmazonS3 {

        // eu-west-1 -> EU_WEST_2 (i.e tf style to enum name)
        val updatedRegion = "eu-west-2".toUpperCase().replace("-", "_")
        val clientRegion = Regions.valueOf(updatedRegion)

        //This code expects that you have AWS credentials set up per:
        // https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html
        return AmazonS3ClientBuilder.standard()
            .withCredentials(DefaultAWSCredentialsProviderChain())
            .withRegion(clientRegion)
            .build()
    }

    //private lateinit var region: String
}
