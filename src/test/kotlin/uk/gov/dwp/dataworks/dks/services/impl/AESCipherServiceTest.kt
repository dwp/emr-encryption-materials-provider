package uk.gov.dwp.dataworks.dks.services.impl

import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherOutputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class AESCipherServiceTest {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    @Test
    fun testEncryptionDecryption() {
        val plaintextDataKey = "czMQLgW/OrzBZwFV9u4EBA=="
        val input = "Original unencrypted text that should come out of decrypt."
        val secureRandom  = SecureRandom()
        val key: Key = SecretKeySpec(Base64.getDecoder().decode(plaintextDataKey), "AES")
        val byteArrayOutputStream = ByteArrayOutputStream()
        val iv = ByteArray(16).apply {
            secureRandom.nextBytes(this)
        }
        val cipherOutputStream = CipherOutputStream(byteArrayOutputStream, encryptingCipher(key, iv))
        val compressingStream =
            CompressorStreamFactory().createCompressorOutputStream(CompressorStreamFactory.BZIP2, cipherOutputStream)
        compressingStream.write(input.toByteArray())
        compressingStream.close()

         val decrypted = AESCipherService.decrypt( plaintextDataKey, Base64.getEncoder().encodeToString(iv), byteArrayOutputStream.toByteArray().inputStream())
        assertEquals(input, decrypted)
    }

     fun encryptingCipher(key: Key, initialisationVector: ByteArray) =
        Cipher.getInstance(AESCipherService.cipherAlgorithm, "BC").apply {
            init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(initialisationVector))
        }

}
