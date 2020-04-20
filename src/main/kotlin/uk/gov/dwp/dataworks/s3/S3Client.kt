package uk.gov.dwp.dataworks.s3

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain
import com.amazonaws.regions.Regions
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.AmazonS3ClientBuilder

object S3Client {
    fun amazonS3(region: String): AmazonS3 {
        val updatedRegion = region.toUpperCase().replace("-", "_")
        val clientRegion = Regions.valueOf(updatedRegion)

        return AmazonS3ClientBuilder.standard()
            .withCredentials(DefaultAWSCredentialsProviderChain())
            .withRegion(clientRegion)
            .build()
    }
}

