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

## Key Java Methods
* ```getEncryptionMaterials(Map<String, String> materialsDescription)```
  * The materialsDescription may contain a ```mode``` parameter:
    * ```<null|blank>``` - indicates that the component is being invoked to provide encryption materials for data about to be written out. (Note: the encryption materials will conform to the ```doubleReuse``` approach - see below)
    * ```"double"``` - indicates that the component is being invoked to decrypt data that has previously been protected using an earlier (now deprecated) encryption mechanism. Code to support this method is currently preserved to support demo data that still relies on this method of protection (ie any files with metadata ```x-amz-meta-x-amz-matdesc``` containing a ```mode``` of ```"double"```)
    * ```"doubleReuse"``` - indicates that the component is being invoked to decrypt data that has previously been protected using the target encryption mechanism (ie any files with metadata ```x-amz-meta-x-amz-matdesc``` containing a ```mode``` of ```"doubleReuse"```)
* ```setConf(Configuration conf)```
  * This method is called when the EMR cluster is first instantiated, and in turn instatiates the DWEncryptionsMaterialsProvider object itself. The various configuration parameters (described in the 'Infrastructure' section above) are passed into the DWEncryptionsMaterialsProvider object, and the init() method is then called.
* ```init()```
  * This method establishes key resources required by the DWEncryptionsMaterialsProvider object, such as:
    * Base64 encoder/decoder
    * JSON parser (via Gson libraries)
  * It also checks that the requisite configuration parameters have been received, and
  * Initialises a cache to hold subsidiary encryption/decryption keypairs (used in the ```doubleReuse``` approach) for up to 24 hours
    * This cache holds any subsidiary keypairs created or re-read back from the S3 bucket pointed to by the ```fs.s3.cse.encr.keypairs.bucket``` configuration parameter
    * This reduces the need to retrieve and decrypt (via DKS) any keypairs that have already been used in the past 24 hours (either to encrypt data being written out from EMR to S3, or decrypt data being read into EMR from S3)
  * Note: this method also reads in from S3 both the public and private halves of a 'master' keypair that is currently being used as a dummy/proxy for the encryption/decryption which will eventually be done by the HSM (via DKS). Once DKS is integrated into the DWEncryptionsMaterialsProvider, this code (and the related configuration parameters - ```fs.s3.cse.rsa.private``` and ```fs.s3.cse.rsa.public``` - and S3 bucket locations) will no longer be required
* ```determineDoubleEncryptionMaterials(Map<String, String> materialsDescription)``` [deprecated]
  * This method provides encryption materials to decrypt data that has previously been protected using an earlier (now deprecated) encryption mechanism. This code is currently preserved to support demo data that still relies on this method of protection (ie any files with metadata ```x-amz-meta-x-amz-matdesc``` containing a ```mode``` of ```"double"```). Once all data has been moved acorss to the ```doubleReuse``` method of protection, this code can be removed.
  * The (deprecated) ```double``` protection method for encrypting data:
    * This is similar to the ```doubleReuse``` protection method (see below), but generates, encrypts and stores (as metadata) a subsidiary keypair **for each file** being stored. Furthermre, the encryption relies on a symmetric key - also one **for each file**, and the result is encrypted using DKS. This is regarded as inefficient and over-engineered. The logic for decryption is as follows:
      * retrieve Base64-encoded subsidiary keypair from materialsDescription (```eem``` parameter)
      * retrieve Base64-encoded DKS-encrypted symmetric key from materialsDescription (```eemkey``` parameter)
      * retrieve Base64-encoded symmetric key's IV from materialsDescription (```eemkeyiv``` parameter)
      * decrypt symmetric key using DKS
      * extract subsidiary keypair from Base64-encoded string
      * extract EEMKeyIV from Base64-encoded string
      * use the now decrypted symmetric key (along with its IV) to decrypt the subsidiary keypair
      * generate an EncryptionMaterials object containing the private key from the now decrypted subsidiary keypair
      * return the generated EncryptionMaterials object
* ```determineDoubleReuseEncryptionMaterials(Map<String, String> materialsDescription)```
  * The ```doubleReuse``` protection method for decrypting data:
    * This improves on the (deprecated) ```double``` protection method by re-using a subsidiary keypair and related symmetric across potentially many files. This is stored separately to the encrypted files themselves (in a discrete s3 bucket - configured using the ```fs.s3.cse.encr.keypairs.bucket``` configuration parameter). The ID of the keypair used to protect each file is stored as metadata with each file (using the ```keyid``` parameter). The logic for decryption is as follows:
      * If the local cache of keypairs has expired (which happens every 24 hours), clear it now
      * If the local keypair cache contains the keypair required to read the file in question - use it (see following steps), otherwise load it from S3 and add it to the local keypair cache. Loading the keypair consists of:
        * use the file's ```keyid``` parameter to retrieve the keypair object from the ```fs.s3.cse.encr.keypairs.bucket``` S3 bucket
        * parse the JSON that is returned into a Java object
        * get the private half of the subsidiary keypair, the related (DKS-encrypted) symmetric key and its IV
        * decrypt symmetric key using DKS
        * extract symmetric key's IV from Base64-encoded string
        * use the symmetric key to decrypt the private half of the subsidiary keypair (ie yielding KeyPair to pass back as EncryptionMaterials)
        * store the keypair in the local keypair cache
      * generate an EncryptionMaterials object containing the private key (retrieved from the local keypair cache)
      * return the generated EncryptionMaterials object
* ```determineDoubleEncryptionMaterialsForEncrypt()```
  * The ```doubleReuse``` protection method for encrypting data (note: there is no equivalent method for the ```double``` method as this is now deprecated). 
  * ```Double``` indicates that protecting data via this mechanism involves two levels of key encryption. 
  * ```Reuse``` acknowledges that the subsidiary keys are reused to encrypt a number of files.
  * The logic for encryption is as follows:
    *  if there is no current subsidiary encryption keypair, or it has expired (ie generated more than 24 hours ago) then generate a new one (the following logic is in the ```generateSubsidiaryKP()``` method within the code):
      * generate new subsidiary keypair
      * encode private half (to DER format)
      * generate a symmetric key to encrypt both halves of the subsidiary keypair (required because the subsidiary keypair is too long to be encrypted with DKS, so DKS will encrypt the symmetric key instead)
      * encrypt the private half of the subsidiary keypair with the symmetric key and convert to base64
      * encrypt the symmetric key with DataWorks' DKS
      * convert everything to Base64 and use the resulting strings to construct a JSON-formatted record to represent the subsidiary keypair, related symmetric key and its IV
      * generate a unique ID and write the JSON keyfile to s3 using ID as the filename
      * store locally as the current keypair and set expiry for max 24 hours
    * generate an EncryptionMaterials object containing the public key of the current (ie locally stored) keypair. This will be used by EMR to encrypt the data before it is stored to S3 via EMRFS. The ecnryoted data will include metadata derived from this EncryptionMaterials object, namely:
      * mode = ```doubleReuse```
      * keyid = ```<ID of the current keypair>```
    * return the generated EncryptionMaterials object
* ```encryptWithDKS(byte[] data)```
  * Note: TODO this function will need to be rewritten so that encryption is performed by the DKS
  * This returns a Base64-encoded string containing an encrypted version of the data supplied as input. The encryption is intended to be equivalent to the 'master key' encryption that will provided by DKS when DKS is integrated
* ```decryptWithDKS(String msg)```
  * Note: TODO this function will need to be rewritten so that decryption is performed by the DKS
  * This accepts a Base64-encoded string as input, representing data previously encrypted using the approach equivalent to the 'master key' encryption that will provided by DKS when DKS is integrated. It returns a byte array representing the decrypted version of the data supplied as input

# Considerations

## DKS

The two methods ```encryptWithDKS()``` and ```decryptWithDKS()``` do not currently take account of key rotation within DKS/HSM - they are currently written as though the 'master key' never changes. Although data stored within S3 (using EMRFS) is never directly encrypted using the enmcryption details within DKS/HSM, the subsidiary keys *are* dependent on DKS/HSM for their encryption. These two methods will need to accommodate returning (for encrypt) and consuming (for decrypt) ID that determione which DKS/HSM keys are to be used in these operations, and the IDs will need to be stored when the subsidiary keypairs are written to S3 (see the generateSubsidiaryKP() method in the code)

# To Do

## Encrypting test data in S3 using the ```doubleReuse``` method

An EMR cluster configured to use the ```DWEncryptionMaterialsProvider``` expects the data it reads to be available in S3 (via the EMRFS protocol) and for that data to be encrypted using the ```doubleReuse``` approach.

A suggested approach to achieving this is:

* Produce a Java-based Lambda function which is triggered when data (unencrypted) is added to a given S3 bucket, and passes that data into the Lambda function.
* The Lambda function will read unencrypted data and encrypt it using encryption materials derived using the approach represented in the ```determineDoubleEncryptionMaterialsForEncrypt()``` method described above. Note: the ```DWEncryptionMaterialsProvider``` class does not encrypt the contents - rather it generates and provides the public half of a subsidiary keypair that is used, in turn, to encrypt a symmetric data key used encrypt the content itself. The logic needs to be:
  * Data is added to a designated 'drop' bucket in S3
  * S3 triggers a lambda function to encrypt the data (as described abve)
  * The lambda receives the unencrypted data
  * The lambda generates a symmetric key and encrypts the data using this key
  * The lambda generates encrypt materials as represented in the ```determineDoubleEncryptionMaterialsForEncrypt()``` method in this the ```DWEncryptionMaterialsProvider``` class
  The lambda writes the encrypted data to an S3 bucket designated to store encrypted data. This includes creating the appropriate metadata that describes the encrypted symmetric key - used to encrypt the data, and details of the subsidiary encryption materials. The resulting metadata for encrypted files will include:
    * ```x-amz-meta-x-amz-key``` - the symmetric key used to encrypt the content
    * ```x-amz-meta-x-amz-iv``` - the IV for the symmetric key used to encrypt the content
    * ```x-amz-meta-x-amz-matdesc``` - the description of theencryption materials used to encrypt the symmetric key:
      * ```keyid``` - the key of the subsidiary keypair
      * ```mode``` - "doubleReuse"