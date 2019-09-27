# Requirements for Encryption Materials Provider

## Runtime
* Java 8 JRE 
* AWS EMR (within Security Configuration)


## Infrastructure 
* AWS S3 bucket to store the jar file
  * named ```<s3-BUCKET>/EncryptionMaterialsProvider-1.0-SNAPSHOT.jar```
* EMR Security Configuration
  * At-rest encryption for Amazon S3 with EMRFS: ```Enabled```
  * S3 encryption
    * Encryption mode ```CSE-Custom```
    * Custom key provider location ```s3://<s3-BUCKET>/EncryptionMaterialsProvider-1.0-SNAPSHOT.jar```
    * Key provider class ```uk.gov.dwp.dataworks.encryptionmaterialsprovider.DWEncryptionMaterialsProvider```
  * At-rest encryption for local disk: ```Enabled```
  * Local disk encryption
    * Key provider type (eg) ```AWS KMS```
    * AWS KMS CMK (eg) ```<KMS-ARN>```
    * Encrypt EBS volumes with EBS encryption (eg) ```Off```



* Parameter Store parameter 
  * named ```data_key_service.currentKeyId```
  * value set to the full ARN for the KMS master key
* AWS user must have permissions for:
  * ```ssm:GetParameter``` on the Parameter store parameter
  * Create Data Key, Encrypt Data Key, Decrypt Data Key for the KMS CMK
  
