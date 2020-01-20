package uk.gov.dwp.dataworks.dks.services

import java.io.InputStream


interface CipherService {
    fun decrypt(key: String, initializationVector: String, encrypted: InputStream): String
}
