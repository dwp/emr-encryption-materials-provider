package uk.gov.dwp.dataworks.encryptionmaterialsprovider

import com.amazonaws.regions.Regions
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.AmazonS3ClientBuilder
import com.amazonaws.services.s3.model.EncryptionMaterials
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
import java.time.LocalDateTime
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class MaterialsResolver(conf: Configuration) {

    private val encryptionKeyPairsBucket: String = conf.get("fs.s3.cse.encr.keypairs.bucket")
    private val keyFactory = java.security.KeyFactory.getInstance("RSA")

    private val clearKeyPairCache = CacheBuilder.newBuilder()
            .expireAfterWrite(24L, TimeUnit.HOURS)
            .build<String, KeyPair>()

    private val s3: AmazonS3 = AmazonS3ClientBuilder.standard()
            .withRegion(Regions.EU_WEST_2)
            .build()

    private lateinit var subsidiaryKeyPair: KeyPair
    private lateinit var subsidiaryFilename: String
    private var subsidiaryExpiry: LocalDateTime = LocalDateTime.now()

    private lateinit var publicKey: PublicKey
    private lateinit var privateKey: PrivateKey

    init {

        val publicKeyUri = URI(conf.get("fs.s3.cse.rsa.public"))
        s3.getObject(publicKeyUri.host, publicKeyUri.path).objectContent.use {
            publicKey = keyFactory.generatePublic(X509EncodedKeySpec(it.readBytes()))
        }

        val privateKeyUri = URI(conf.get("fs.s3.cse.rsa.private"))
        s3.getObject(privateKeyUri.host, privateKeyUri.path).objectContent.use {
            privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(it.readBytes()))
        }
    }

    fun getEncryptionMaterials(materialsDescription: MutableMap<String, String>?): EncryptionMaterials {
        return when(materialsDescription?.get("mode")) {
            "doubleReuse" -> determineDoubleReuseEncryptionMaterials(materialsDescription)
            null -> throw RuntimeException("Encryption Materials Not Initialised")
            else -> determineDoubleEncryptionMaterialsForEncrypt()
        }
    }

    private fun determineDoubleReuseEncryptionMaterials(materialsDescription: MutableMap<String, String>): EncryptionMaterials {
        val decryptionKeyPair: KeyPair?
        val keyId = materialsDescription.getOrDefault("keyid", "fdf11ee8-644d-4c2e-a9de-698af670a618")

        if(clearKeyPairCache.getIfPresent(keyId) == null) {
            decryptionKeyPair = clearKeyPairCache.getIfPresent(keyId)
        }
        else {
            val subsidiaryKey = readFromS3(encryptionKeyPairsBucket, keyId)
            val mapKpSubsidiary: Map<String, String> = Gson()
                    .fromJson(subsidiaryKey, object : TypeToken<HashMap<String, String>>() {}.type)

            val symEncryptedPrivKeyPair = mapKpSubsidiary["priv"]?.toByteArray()

            val symKeyBytes = decryptWithDKS(mapKpSubsidiary["symkey"] ?: "")
            val secretSymKey = SecretKeySpec(symKeyBytes, "AES")
            val symKeyIv = Base64.getDecoder().decode(mapKpSubsidiary["symkeyiv"])

            val cipherSymKey = Cipher.getInstance("AES/GCM/NoPadding")
            cipherSymKey.init(Cipher.DECRYPT_MODE, secretSymKey, IvParameterSpec(symKeyIv))

            val keyPairBytes = cipherSymKey.doFinal(Base64.getDecoder().decode(symEncryptedPrivKeyPair))
            decryptionKeyPair = KeyPair(null, keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyPairBytes)))
            clearKeyPairCache.put(keyId, decryptionKeyPair)
        }

        return EncryptionMaterials(decryptionKeyPair).addDescription("mode", "doubleReuse")
    }

    private fun determineDoubleEncryptionMaterialsForEncrypt(): EncryptionMaterials {
        if(subsidiaryFilename.isBlank() || LocalDateTime.now().isAfter(subsidiaryExpiry)) {
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

    private fun readFromS3(bucket: String, key: String): String {
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