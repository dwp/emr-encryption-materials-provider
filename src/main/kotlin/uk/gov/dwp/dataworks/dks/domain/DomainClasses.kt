package uk.gov.dwp.dataworks.dks.domain


data class DataKeyResult(val dataKeyEncryptionKeyId: String, val plaintextDataKey: String, val ciphertextDataKey: String)
