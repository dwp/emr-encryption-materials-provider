package uk.gov.dwp.dataworks.dks.client

interface DKSClient {

    fun decryptKey(encryptionKeyId: String, encryptedKey: String): String

}
