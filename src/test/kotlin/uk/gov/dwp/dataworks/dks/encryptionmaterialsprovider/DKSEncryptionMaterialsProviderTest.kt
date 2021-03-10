package uk.gov.dwp.dataworks.dks.encryptionmaterialsprovider

import org.junit.jupiter.api.Test
import org.mockito.BDDMockito.given
import org.mockito.BDDMockito.then
import org.mockito.Mockito
import org.mockito.Mockito.mock
import uk.gov.dwp.dataworks.dks.domain.DataKeyResult
import uk.gov.dwp.dataworks.dks.services.KeyService
import kotlin.time.ExperimentalTime


@ExperimentalTime
class DKSEncryptionMaterialsProviderTest {


    @Test
    fun testGetEncryptionMaterialsForEncryption() {

        val keyService = mock(KeyService::class.java)
        val dataKeyResult = DataKeyResult("keyId", "plainTextKey", "cipher")
        given(keyService.batchDataKey()).willReturn(dataKeyResult)
        val dksEncryptionMaterialsProvider = DKSEncryptionMaterialsProvider()
        dksEncryptionMaterialsProvider.initializeKeyservice(keyService)
        val map = mutableMapOf<String, String?>()
        dksEncryptionMaterialsProvider.getEncryptionMaterials(map)
        then(keyService).should(Mockito.times(1)).batchDataKey()
    }

    @Test
    fun testGetEncryptionMaterialsForDecryption() {
        val keyId = "keyid"
        val encryptedKey = "encryptedkey"
        val keyService = mock(KeyService::class.java)
        given(keyService.decryptKey(keyId, encryptedKey)).willReturn("plainTextKey")
        val dksEncryptionMaterialsProvider = DKSEncryptionMaterialsProvider()
        dksEncryptionMaterialsProvider.initializeKeyservice(keyService)
        val map = mutableMapOf<String, String?>()
        map.put("keyid",keyId)
        map.put("encryptedkey",encryptedKey)
        dksEncryptionMaterialsProvider.getEncryptionMaterials(map)
        then(keyService).should(Mockito.times(1)).decryptKey(keyId,encryptedKey)
    }
}
