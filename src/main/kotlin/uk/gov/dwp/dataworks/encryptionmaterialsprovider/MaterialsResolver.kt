package uk.gov.dwp.dataworks.encryptionmaterialsprovider

import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.EncryptionMaterials
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.apache.hadoop.conf.Configuration
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

class MaterialsResolver(conf: Configuration, private val s3: AmazonS3, cacheExpirySeconds: Long) {

    private val requiredConfiguration = setOf("fs.s3.cse.encr.keypairs.bucket", "fs.s3.cse.rsa.public", "fs.s3.cse.rsa.private")
    private val encryptionKeyPairsBucket: String
    private val keyFactory = java.security.KeyFactory.getInstance("RSA")

    val clearKeyPairCache: Cache<String, KeyPair> = CacheBuilder.newBuilder()
            .expireAfterWrite(Duration.ofSeconds(cacheExpirySeconds))
            .build()

    private lateinit var subsidiaryKeyPair: KeyPair
    lateinit var subsidiaryFilename: String
    private var subsidiaryExpiry: LocalDateTime = LocalDateTime.now()

    private val publicKey: PublicKey
    private val privateKey: PrivateKey

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
        val notFound = requiredConfiguration.filter { conf.get(it) == null || conf.get(it).isEmpty()}
        check(notFound.isEmpty()) { "Required configuration items $notFound were not found or were empty" }
    }

    fun getEncryptionMaterials(materialsDescription: MutableMap<String, String?>): EncryptionMaterials {
        val keyId: String = materialsDescription["keyid"] ?: "fdf11ee8-644d-4c2e-a9de-698af670a618"
        return when(materialsDescription["mode"]) {
            "doubleReuse" -> determineDoubleReuseEncryptionMaterials(keyId)
            null -> throw RuntimeException("Encryption Materials Not Initialised")
            else -> determineDoubleEncryptionMaterialsForEncrypt()
        }
    }

    private fun determineDoubleReuseEncryptionMaterials(keyId: String): EncryptionMaterials {
        val decryptionKeyPair: KeyPair?

        if(clearKeyPairCache.getIfPresent(keyId) != null) {
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
            clearKeyPairCache.put(keyId, decryptionKeyPair)
        }

        return EncryptionMaterials(decryptionKeyPair).addDescription("mode", "doubleReuse")
    }

    private fun determineDoubleEncryptionMaterialsForEncrypt(): EncryptionMaterials {
        if(!::subsidiaryFilename.isInitialized || LocalDateTime.now().isAfter(subsidiaryExpiry)) {
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
    }

    fun readFromS3(bucket: String, key: String): String {
        s3.getObject(bucket, key).objectContent.use {
            return String(it.readBytes())
        }
    }

    private fun encryptWithDKS(data: ByteArray): String {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(data)
        return encodeToBase64(encryptedBytes)
    }

    private fun decryptWithDKS(msg: String): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(Base64.getDecoder().decode(msg))
    }

    private fun encodeToBase64(toEncrypt: ByteArray): String {
        return String(Base64.getEncoder().encode(toEncrypt))
    }
}