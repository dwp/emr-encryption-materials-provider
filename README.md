# DO NOT USE THIS REPO - MIGRATED TO GITLAB

# Spike - Decryption in spark vs transparent EMRFS decryption (DW-3239 vs DW-3234)   for the ingested data by HTME
EMRFS transparent Encryption:
1. EMRFS generates data key , encrypts the data with the generated data key 
2. Encrypts the data key with KEK provided by custom encryption materials provider

EMRFS transparent Decryption:
1. EMRFS decrypts the  encrypted data key in the S3 metadata with KEK provided by custom encryption materials provider
2. Decrypts the data with the decrypted data key

As  EMRFS expects the key encryption material(KEK) from  materials provider  to decrypt the encrypted data key,  It is not possible to decrypt the data ingested by HTME through transparent EMRFS decryption as their design doesn't not  let the master key material (private key) 
leave cloud HSM. Therefore EMRFS transparent  decryption cannot be leveraged to decrypt that ingested data. So Spark process has to decrypt the ingested data.However further stages in the data pipeline can leverage emrfs transparent  encryption/decryption while persisting data to s3

# References
* Read Option 2: Using a Master Key Stored Within Your Application in https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingClientSideEncryption.html  

# Implementation details of EMRFS transparent encryption/decryption: 

## EMR Encryption Materials Provider 
An EMR Security Configuration plugin implementing transparent client-side encryption and decryption between EMR and data persisted in S3 (via EMRFS).

## Build requirements
* Java 8 jdk
* Gradle


## Build instructions
Gradle will fetch required packages and action all of the building. You can start the process by using the gradle wrapper

```bash
./gradlew build shadow
```
Note that the shadow jar includes the Kotlin standard library in the resultant file.

### Snyk Issues
There are some issues flagged by Snyk, however they are in libraries we link to in EMR, and hence cannot be directly upgraded.

## Runtime
* Java 8 JRE 
* AWS EMR (within Security Configuration) in the same VPC or VPC that can peer to DKS VPC 


## Infrastructure 
* AWS S3 bucket to store the jar file
  * named ```<s3-BUCKET>/EncryptionMaterialsProvider-$Version.jar```
* EMR Security Configuration
  * At-rest encryption for Amazon S3 with EMRFS: ```Enabled```
  * S3 encryption
    * Encryption mode ```CSE-Custom```
    * Custom key provider location ```s3://<S3-BUCKET>/EncryptionMaterialsProvider-$Version.jar```
    * Key provider class ```uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider.DKSEncryptionMaterialsProvider```
  * At-rest encryption for local disk: ```Enabled```
  * Local disk encryption
    * Key provider type (eg) ```AWS KMS```
    * AWS KMS CMK (eg) ```<KMS-ARN>```
    * Encrypt EBS volumes with EBS encryption (eg) ```Off```
  * EMR Cluster Security Configuration
    * AWS EMR's ```EC2 Instance Profile``` Role must include permissions for:
      * ```s3:*```
    * AWS EMR's ```EMR Role``` must include permissions for:
      * ```s3:CreateBucket```
      * ```s3:Get*```
      * ```s3:List*```

## S3 bucket locations used by this component
* ```<S3-BUCKET/encryption_materials_provider_jar>``` - holds the Java JAR file representing this component itself

# Logic

This component implements the ```EncryptionMaterialsProvider``` interface

## Key Kotlin Methods
* ```getEncryptionMaterials(Map<String, String> materialsDescription)```
  * The materialsDescription may contain a ```keyid```  and  ```encryptedkey``` parameter:
    * ```<null & null>``` - indicates that the component is being invoked to provide encryption materials for data about to be written out.
    * ```"<not null & null>"``` - indicates that the component is being invoked to decrypt data that has previously been protected using the target encryption mechanism
* ```setConf(Configuration conf)```
  * This method is called when the EMR cluster is first instantiated, and in turn instantiates  the DKSEncryptionMaterialsProvider object itself. The various configuration parameters (described in the 'Infrastructure' section above) are passed into the DKSEncryptionMaterialsProvider object, and the init() method is then called.
* ```init()```
  * This method establishes key resources required by the DKSEncryptionMaterialsProvider object, such as:
  * DKS properties to initialize the secure  http client provider to  communicate with DKS
  * It also checks that the requisite configuration parameters have been received, and
* ```getMaterialForDecryption(keyId: String?, encryptedKey: String?): EncryptionMaterials```
    * The logic for decryption is as follows:
        * Retrieve the  file's ```keyid``` and ```encryptedkey``` parameters
        * Get the plain text key for the encryptedkey by passing parameters  ```keyid``` and ```encryptedkey``` to DKS service 
      * generate an EncryptionMaterials object containing the plain symmetric  key (retrieved from the local  cache)
      * return the generated EncryptionMaterials object
* ```getMaterialForEncryption(): EncryptionMaterials```
  * The logic for encryption is as follows:
      * Generate the plain and encrypted symmetric key with DKS
    * generate an EncryptionMaterials object containing the symmetric  key . This will be used by EMR to encrypt the data before it is stored to S3 via EMRFS. The ecnryoted data will include metadata derived from this EncryptionMaterials object, namely:
      * encryptedkey = ```encrypted version of the symmetric key ```
      * keyid = ```<ID of the current cloud HSM  keypair>```
    * return the generated EncryptionMaterials object


# Testing EMRFS transparent encryption/decryption

An EMR cluster with in the same VPC or VPC that can peer to DKS VPC needs to be configured to use the ```DKSEncryptionMaterialsProvider``` which expects the data to be read to be available in S3 (via the EMRFS protocol) and for that data to be encrypted 

A suggested approach to achieving this is:
* Bring up a cluster  with a custom  security configuration as defined in the infrastructure 
* save  the below python code in WRITE.py file in the master node of the cluster and execute PYTHONSTARTUP=WRITE.py pyspark 
     ```from pyspark.sql import *
    
     Employee = Row("firstName", "lastName", "email", "salary")
     employee1 = Employee('Basher', 'armbrust', 'bash@edureka.co', 100000)
     department1 = Row(id='123456', name='HR')
     departmentWithEmployees1 = Row(department=department1, employees=[employee1, employee2, employee5])
     departmentsWithEmployees_Seq = [departmentWithEmployees1]
     dframe = spark.createDataFrame(departmentsWithEmployees_Seq)
     dframe.show()
     dframe.write.parquet("s3://<BUCKET_URI>/<PREFIX>/0001.parquet")```

* verify the metadata of the s3 object for 
    ```keyid``` 
    ```encryptedkey```
* Save the  parquet file to READ.py and execute PYTHONSTARTUP=READ.py pyspark
    ```
    df2 = spark.read.parquet("s3://<BUCKET_URI>/<PREFIX>/0001.parquet") 
    df2.show()```
# Jar upload to s3 bucket via mirror job

publish-github-release task in .circleci/config.yml  generates two types of jar assets in https://github.com/dwp/emr-encryption-materials-provider/releases out of which encryption-materials-provider-xxx-all.jar is a uber/fat jar
that is uploaded to s3 artefact bucket via mirror-job.yml which is used in security configuration of emr clusters for transparent encryption.

  



