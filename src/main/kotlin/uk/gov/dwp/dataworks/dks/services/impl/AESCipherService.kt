package uk.gov.dwp.dataworks.dks.services.impl

import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import uk.gov.dwp.dataworks.dks.services.CipherService
import java.io.BufferedReader
import java.io.InputStream
import java.security.Key
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AESCipherService : CipherService {
     const val cipherAlgorithm: String = "AES/CTR/NoPadding"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override fun decrypt(key: String, initializationVector: String, encrypted: InputStream): String {
        val keySpec: Key = SecretKeySpec(Base64.getDecoder().decode(key), "AES")
        val cipher = Cipher.getInstance(cipherAlgorithm, "BC").apply {
            init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(Base64.getDecoder().decode(initializationVector)))
        }

        val decryptedStream = CipherInputStream(encrypted, cipher)
        val decompressedStream = CompressorStreamFactory().createCompressorInputStream(CompressorStreamFactory.BZIP2, decryptedStream)
        return decompressedStream.bufferedReader().use(BufferedReader::readText)

    }
}
