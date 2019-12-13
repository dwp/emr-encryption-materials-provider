package uk.gov.dwp.dataworks.encryptionmaterialsprovider

import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.EncryptionMaterials
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.apache.hadoop.conf.Configuration
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URI
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Duration
import java.time.LocalDateTime
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Supporting class to [DWEncryptionMaterialsProvider] which handles key creation, retrieval and
 * encryption / decryption of materials. After initialisation, [getEncryptionMaterials] can be called
 * with "mode" metadata passed in to perform tasks. See KDoc for method for further info.
 *
 * Note that this uses a temporary static public-private [KeyPair] to encrypt and decrypt until such time
 * as code is written to use the DKS service. See TODO articles in this code for what needs removing.
 */
class MaterialsResolver(conf: Configuration, private val s3: AmazonS3, cacheExpirySeconds: Long) {

    //TODO Remove "fs.s3.cse.rsa.public" and "fs.s3.cse.rsa.public" when DKS real code added
    private val requiredConfiguration = setOf("fs.s3.cse.encr.keypairs.bucket", "fs.s3.cse.rsa.public", "fs.s3.cse.rsa.private")
    private val encryptionKeyPairsBucket: String
    private val keyFactory = java.security.KeyFactory.getInstance("RSA")

    val clearKeyPairCache: Cache<String, KeyPair> = CacheBuilder.newBuilder()
        .expireAfterWrite(Duration.ofSeconds(cacheExpirySeconds))
        .build()

    private lateinit var subsidiaryKeyPair: KeyPair
    lateinit var subsidiaryFilename: String
    private var subsidiaryExpiry: LocalDateTime = LocalDateTime.now()

    private val publicKey: PublicKey //TODO Remove this and the privateKey when DKS is implemented
    private val privateKey: PrivateKey

    /**
     * Initialise the [MaterialsResolver]. This will ensure that required conf from the [Configuration] object
     * is present and extract it to vars for later use.
     */
    init {
        ensureConfigurationHasRequired(conf)
        encryptionKeyPairsBucket = conf.get("fs.s3.cse.encr.keypairs.bucket")
        val publicKeyUri = URI(conf.get("fs.s3.cse.rsa.public"))
        publicKey = s3.getObject(publicKeyUri.host, publicKeyUri.path.removePrefix("/")).objectContent.use {
            keyFactory.generatePublic(X509EncodedKeySpec(it.readBytes()))
        }

        val privateKeyUri = URI(conf.get("fs.s3.cse.rsa.private"))
        privateKey = s3.getObject(privateKeyUri.host, privateKeyUri.path.removePrefix("/")).objectContent.use {
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(it.readBytes()))
        }
    }

    private fun ensureConfigurationHasRequired(conf: Configuration) {
        val notFound = requiredConfiguration.filter { conf.get(it) == null || conf.get(it).isEmpty() }
        check(notFound.isEmpty()) { "Required configuration items $notFound were not found or were empty" }
    }

    /**
     * Entry point for this class. Based on the value of "mode", do the following:
     * * doubleReuse - return a cached key based on the "keyid" if same keyid has been requested
     *    in the previous [cacheExpirySeconds] seconds. Otherwise, read the subsidiary key from S3,
     *    decode it from it's Base64 format and use it to determine the decryption [KeyPair] required.
     *    The determined key is also added to the cache for fast retrieval next time.
     * * null - Throw an exception, as "mode" has not been passed in
     * * anything else - This is assumed to be a request for encryption, and a subsidiary key will
     *    be created and saved to s3 the first call and every subsequent call 24hrs after the last
     *    generation. After creation of the subsidiary key, [EncryptionMaterials] are returned using
     *    the public key of the subsidiary key and a keyId of the filename in s3 which the subsidiary
     *    key was retrieved from
     */
    fun getEncryptionMaterials(materialsDescription: MutableMap<String, String?>): EncryptionMaterials {
        val keyId: String = materialsDescription["keyid"] ?: "fdf11ee8-644d-4c2e-a9de-698af670a618"
        logger.info("Got request for EncryptionMaterials with mode: ${materialsDescription["mode"]}, Key ID: $keyId")
        return when (materialsDescription["mode"]) {
            "doubleReuse" -> determineDoubleReuseEncryptionMaterials(keyId)
            //null -> throw RuntimeException("Encryption Materials Not Initialised")
            else -> determineDoubleEncryptionMaterialsForEncrypt()
        }
    }

    private fun determineDoubleReuseEncryptionMaterials(keyId: String): EncryptionMaterials {
        val decryptionKeyPair: KeyPair?

        if (clearKeyPairCache.getIfPresent(keyId) != null) {
            logger.debug("Returning key with ID $keyId from in-memory cache")
            decryptionKeyPair = clearKeyPairCache.getIfPresent(keyId)
        }
        else {
            val subsidiaryKey = readFromS3(encryptionKeyPairsBucket, keyId)
            val keyPairSubsidiary: Map<String, String> = Gson()
                .fromJson(subsidiaryKey, object : TypeToken<HashMap<String, String>>() {}.type)

            val symEncryptedPrivKeyPair = Base64.getDecoder().decode(keyPairSubsidiary["priv"]?.toByteArray())

            val symKeyBytes = decryptWithDKS(keyPairSubsidiary["symkey"] ?: "")
            val secretSymKey = SecretKeySpec(symKeyBytes, "AES")
            val symKeyIv = Base64.getDecoder().decode(keyPairSubsidiary["symkeyiv"])

            val cipherSymKey = Cipher.getInstance("AES/GCM/NoPadding")
            cipherSymKey.init(Cipher.DECRYPT_MODE, secretSymKey, GCMParameterSpec(128, symKeyIv))

            val keyPairBytes = cipherSymKey.doFinal(symEncryptedPrivKeyPair)
            decryptionKeyPair = KeyPair(null, keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyPairBytes)))
            logger.debug("Adding key with ID $keyId to in-memory cache")
            clearKeyPairCache.put(keyId, decryptionKeyPair)
        }

        return EncryptionMaterials(decryptionKeyPair).addDescription("mode", "doubleReuse")
    }

    private fun determineDoubleEncryptionMaterialsForEncrypt(): EncryptionMaterials {
        if (!::subsidiaryFilename.isInitialized || LocalDateTime.now().isAfter(subsidiaryExpiry)) {
            logger.info("$subsidiaryExpiry has passed, creating new subsidiary key pair")
            generateSubsidiaryKeyPair()
        }

        val secretKeyKeyPair = KeyPair(subsidiaryKeyPair.public, null)
        return EncryptionMaterials(secretKeyKeyPair)
            .addDescription("mode", "doubleReuse")
            .addDescription("keyid", subsidiaryFilename)
    }

    private fun generateSubsidiaryKeyPair() {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(1024)

        val keyPairSubsidiary = keyPairGenerator.generateKeyPair()
        val secretSymKey = KeyGenerator.getInstance("AES").generateKey()
        val cipherSymKey = Cipher.getInstance("AES/GCM/NoPadding")
        cipherSymKey.init(Cipher.ENCRYPT_MODE, secretSymKey)

        val encryptedKeyPairSubsidiaryPriv = cipherSymKey.doFinal(keyPairSubsidiary.private.encoded)

        val b64EncryptedSymKey = encryptWithDKS(secretSymKey.encoded)
        val subsidiaryEncryptionMaterials = """{"priv":"${encodeToBase64(encryptedKeyPairSubsidiaryPriv)}",
            |"symkeyiv":"${encodeToBase64(cipherSymKey.iv)}",
            |"symkey":"$b64EncryptedSymKey"}""".trimMargin()

        val guidFilename = UUID.randomUUID().toString()

        s3.putObject(encryptionKeyPairsBucket, guidFilename, subsidiaryEncryptionMaterials)

        subsidiaryFilename = guidFilename
        subsidiaryKeyPair = keyPairSubsidiary
        subsidiaryExpiry = LocalDateTime.now().plusHours(24L)
        logger.info("Subsidiary key pair created with GUID $guidFilename, valid until $subsidiaryExpiry")
    }

    fun readFromS3(bucket: String, key: String): String {
        s3.getObject(bucket, key).objectContent.use {
            return String(it.readBytes())
        }
    }

    /**
     * Encrypt the given [ByteArray] data via the DKS service.
     */
    //TODO Update with real DKS code
    private fun encryptWithDKS(data: ByteArray): String {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(data)
        return encodeToBase64(encryptedBytes)
    }

    /**
     * Decrypt the given [String] via the DKS service
     */
    //TODO Update with real DKS code
    private fun decryptWithDKS(msg: String): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(Base64.getDecoder().decode(msg))
    }

    private fun encodeToBase64(toEncrypt: ByteArray): String {
        return String(Base64.getEncoder().encode(toEncrypt))
    }

    companion object {
        val logger: Logger = LoggerFactory.getLogger(MaterialsResolver::class.toString())
    }
}
