package uk.gov.dwp.dataworks.encryptionmaterialsprovider

import com.adobe.testing.s3mock.junit5.S3MockExtension
import com.amazonaws.services.s3.AmazonS3
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.PutObjectRequest
import org.apache.hadoop.conf.Configuration
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator


@ExtendWith(S3MockExtension::class)
class MaterialsResolverTest {

    private val dummyBucket = "dummybucket"
    private val publicKeyPath = "publicKeyPath"
    private val privateKeyPath = "privateKeyPath"
    private val subsidiaryKeyId = "subsidiaryKeyId"

    private lateinit var materialsResolver: MaterialsResolver
    private lateinit var s3Client: AmazonS3
    private lateinit var fakePublicPrivateKey: KeyPair

    @BeforeEach
    fun init(s3Client: AmazonS3) {
        fakePublicPrivateKey = generateTestKeyPair()
        val subsidiaryKey = generateSubsidiaryKey()
        this.s3Client = s3Client
        s3Client.createBucket(dummyBucket)
        s3Client.putObject(PutObjectRequest(dummyBucket, publicKeyPath,
                fakePublicPrivateKey.public.encoded.inputStream(), ObjectMetadata()))
        s3Client.putObject(PutObjectRequest(dummyBucket, privateKeyPath,
                fakePublicPrivateKey.private.encoded.inputStream(), ObjectMetadata()))
        s3Client.putObject(PutObjectRequest(dummyBucket, subsidiaryKeyId,
                subsidiaryKey.byteInputStream(), ObjectMetadata()))

        val conf = Configuration()
        conf.set("fs.s3.cse.encr.keypairs.bucket", dummyBucket)
        conf.set("fs.s3.cse.rsa.public", "s3://dummybucket/publicKeyPath")
        conf.set("fs.s3.cse.rsa.private", "s3://dummybucket/privateKeyPath")
        materialsResolver = MaterialsResolver(conf, s3Client, 10L)
    }

    private fun generateTestKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        val random = SecureRandom.getInstance("SHA1PRNG", "SUN")
        val md = MessageDigest.getInstance("SHA-256");
        random.setSeed(md.digest("seed".toByteArray()))
        keyGen.initialize(1024, random)
        return keyGen.genKeyPair()
    }

    private fun generateSubsidiaryKey(): String {
        val subsidiaryKeyPair = generateTestKeyPair()
        val cipherSymKey = Cipher.getInstance("AES/GCM/NoPadding")
        val secretSymKey = KeyGenerator.getInstance("AES").generateKey()
        val b64EncryptedSymKey = encryptWithFakeKey(secretSymKey.encoded)
        cipherSymKey.init(Cipher.ENCRYPT_MODE, secretSymKey)
        return """{"priv":"${String(Base64.getEncoder().encode(subsidiaryKeyPair.private.encoded))}",
            |"symkeyiv":"${String(Base64.getEncoder().encode(cipherSymKey.iv))}",
            |"symkey":"${String(b64EncryptedSymKey)}"}""".trimMargin()
    }

    private fun encryptWithFakeKey(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, fakePublicPrivateKey.public)
        val encryptedBytes = cipher.doFinal(data)
        return Base64.getEncoder().encode(encryptedBytes)
    }

    @Test
    fun failsToInitialiseOnMissingConfigurationItems() {
        assertThrows<IllegalStateException>(
                "Required configuration items [fs.s3.cse.encr.keypairs.bucket, fs.s3.cse.rsa.public, fs.s3.cse.rsa.private] were not found or were empty")
        { MaterialsResolver(Configuration(), s3Client, 10L) }
    }

    @Test
    fun returnsDoubleReuseMaterialsWhenDoubleReuseModeRequested() {
        val encryptionMaterials = materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "doubleReuse"), Pair("keyid", subsidiaryKeyId)))
        assertThat(encryptionMaterials.materialsDescription["mode"]).isEqualTo("doubleReuse")
    }

    @Test
    fun returnsDoubleReuseMaterialsWhenBlankModeRequested() {
        var encryptionMaterials = materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "")))
        assertThat(encryptionMaterials.materialsDescription["mode"]).isEqualTo("doubleReuse")

        encryptionMaterials = materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "someOther")))
        assertThat(encryptionMaterials.materialsDescription["mode"]).isEqualTo("doubleReuse")
    }

    @Test
    fun throwsExceptionWhenNullModeRequested() {
        assertThrows<RuntimeException>("Encryption Materials Not Initialised")
        { materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", null))) }
    }

    @Test
    fun cacheWillExpungeKeyAfterExpiryTime() {
        //Cache is empty
        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(0)

        //Add to cache
        materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "doubleReuse"), Pair("keyid", subsidiaryKeyId)))
        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(1)
        // Wait for cache expiry
        Thread.sleep(150)
        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(0)
    }

    @Test
    fun willReturnKeyPairFromCacheWhenPresent() {
        val testKeyPair = generateTestKeyPair()
        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(0)
        materialsResolver.clearKeyPairCache.put("testKey", testKeyPair)
        val encMaterials = materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "doubleReuse"), Pair("keyid", "testKey")))

        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(1)
        assertThat(encMaterials.keyPair).isEqualTo(testKeyPair)
    }

    @Test
    fun willReadKeyPairFromS3IfNotInCache() {
        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(0)
        val encMaterials = materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "doubleReuse"), Pair("keyid", subsidiaryKeyId)))

        assertThat(materialsResolver.clearKeyPairCache.size()).isEqualTo(1)
        assertThat(encMaterials.keyPair).isEqualTo(fakePublicPrivateKey)
    }

    @Test
    fun willCreateSubsidiaryIfFilenameNotInitialised() {
        assertThrows<UninitializedPropertyAccessException>("lateinit property subsidiaryFilename has not been initialized")
            { materialsResolver.subsidiaryFilename }
        materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "someOther"), Pair("keyid", publicKeyPath)))
        assertThat(materialsResolver.subsidiaryFilename).isNotBlank()
    }

    @Test
    fun willWriteSubsidiaryToS3() {
        assertThrows<UninitializedPropertyAccessException>("lateinit property subsidiaryFilename has not been initialized")
        { materialsResolver.subsidiaryFilename }
        materialsResolver.getEncryptionMaterials(mutableMapOf(Pair("mode", "someOther"), Pair("keyid", publicKeyPath)))
        assertThat(materialsResolver.subsidiaryFilename).isNotNull()
        assertThat(s3Client.doesObjectExist(dummyBucket, materialsResolver.subsidiaryFilename))
        val subsidiaryKey = s3Client.getObject(dummyBucket, materialsResolver.subsidiaryFilename)
        val subsidiaryKeyContent = subsidiaryKey.objectContent.use { String(it.readBytes()) }
        assertThat(subsidiaryKeyContent).contains("priv", "symkeyiv", "symkey")
    }

    @Test
    fun canReadFromS3() {
        val expected = "thisissomecontent"
        assertThat(s3Client.doesObjectExist(dummyBucket, "dummyObject"))
        s3Client.putObject(dummyBucket, "dummyObject", expected)

        val actual = materialsResolver.readFromS3(dummyBucket, "dummyObject")
        assertThat(actual).isEqualTo(expected)
    }
}