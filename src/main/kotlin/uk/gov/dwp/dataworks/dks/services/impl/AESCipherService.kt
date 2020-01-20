package app.services.impl

import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.Logger
import org.slf4j.LoggerFactory
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
    private const val  cipherAlgorithm: String = "AES/CTR/NoPadding"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    override fun decrypt(key: String, initializationVector: String, content: InputStream): String {
        val keySpec: Key = SecretKeySpec(Base64.getDecoder().decode(key), "AES")
        val cipher = Cipher.getInstance(cipherAlgorithm, "BC").apply {
            init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(Base64.getDecoder().decode(iv)))
        }

        val decryptedStream = CipherInputStream(content, cipher)
        val decompressedStream = CompressorStreamFactory().createCompressorInputStream(CompressorStreamFactory.BZIP2, decryptedStream)
        return decompressedStream.bufferedReader().use(BufferedReader::readText)

    }
}
