# EMR Encryption Materials Provider

An EMR Security Configuration plugin implementing transparent client-side encryption and decryption between EMR and data persisted in S3 (via EMRFS).

# Build requirements

* Java 8 jdk
* Gradle


# Build instructions
Gradle will fetch required packages and action all of the building. You can start the process by using the gradle wrapper

```bash
./gradlew build
```


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
    * Custom key provider location ```s3://<S3-BUCKET>/EncryptionMaterialsProvider-1.0-SNAPSHOT.jar```
    * Key provider class ```uk.gov.dwp.dataworks.encryptionmaterialsprovider.DWEncryptionMaterialsProvider```
  * At-rest encryption for local disk: ```Enabled```
  * Local disk encryption
    * Key provider type (eg) ```AWS KMS```
    * AWS KMS CMK (eg) ```<KMS-ARN>```
    * Encrypt EBS volumes with EBS encryption (eg) ```Off```
  * EMR Cluster Configuration (see note about temporary keys below)
    * ```[{"classification":"emrfs-site", "properties":{"fs.s3.cse.rsa.private":"s3://<S3-BUCKET>/encryption_materials_provider_temporary_keys/id_rsa.der", "fs.s3.cse.rsa.name":"cse-rsa-name", "fs.s3.cse.encr.keypairs.bucket":"<S3-BUCKET>/encryption_keypairs", "fs.s3.cse.rsa.public":"s3://<S3-BUCKET>/encryption_materials_provider_temporary_keys/id_rsa_pub.der"}, "configurations":[]}]```
  * EMR Cluster Security Configuration
    * AWS EMR's ```EC2 Instance Profile``` Role must include permissions for:
      * ```s3:*```
    * AWS EMR's ```EMR Role``` must include permissions for:
      * ```s3:CreateBucket```
      * ```s3:Get*```
      * ```s3:List*```

## Temporary Keys 
* This component is not currently integrated with the Data Key Service (DKS).
* Instead the component includes two methods that encrypt and decrypt subsidiary encryption details using a local keypair. This keypair is not required when the component becomes integrated with DKS. The two methods are:
  * ```DWEncryptionMaterialsProvider:encryptWithDKS()```
  * ```DWEncryptionMaterialsProvider:decryptWithDKS()```
* The two halves of the keypair need to be ```der``` formatted and stored in an S3 bucket. The location is configured in EMR using the following configuration parameters (see 'EMR Cluster Security Configuration' above):
  * ```fs.s3.cse.rsa.private```
  * ```fs.s3.cse.rsa.public```

## S3 bucket locations used by this component
* ```<S3-BUCKET/encryption_keypairs>``` - holds subsidiary data keys (encrypted in turn with DKS)
* ```<S3-BUCKET/encryption_materials_provider_jar>``` - holds the Java JAR file representing this component itself
* ```<S3-BUCKET/encryption_materials_provider_temporary_keys>``` - holds the temporary keys (see above) that currently act as a proxy for DKS

# Logic

This component implements the ```EncryptionMaterialsProvider``` interface

## Methods
* EncryptionMaterials getEncryptionMaterials(Map<String, String> materialsDescription)
  * The materialsDescription may contain a ```mode``` parameter:
    * ```<null|blank>``` - indicates that the component is being invoked to provide encryption materials for data about to be written out
    * ```"double"``` - indicates that the component is being invoked to decrypt data that has previously been protected using an earlier (now deprecated) encryption mechanism. Code to support this method is currently preserved to support demo data that still relies on this method of protection (ie any files with metadata ```x-amz-meta-x-amz-matdesc``` containing a ```mode``` of ```"double"```)
    * ```"doubleReuse"``` - indicates that the component is being invoked to decrypt data that has previously been protected using the target encryption mechanism (ie any files with metadata ```x-amz-meta-x-amz-matdesc``` containing a ```mode``` of ```"doubleReuse"```)
  
