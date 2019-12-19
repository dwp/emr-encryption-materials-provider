package uk.gov.dwp.dataworks.dks.services

import uk.gov.dwp.dataworks.dks.domain.DataKeyResult
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyDecryptionException
import uk.gov.dwp.dataworks.dks.exceptions.DataKeyServiceUnavailableException

interface KeyService {

    @Throws(DataKeyServiceUnavailableException::class, DataKeyDecryptionException::class)
    fun decryptKey(encryptionKeyId: String, encryptedKey: String): String

    @Throws(DataKeyServiceUnavailableException::class)
    fun batchDataKey(): DataKeyResult
}
