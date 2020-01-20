package uk.gov.dwp.dataworks.decryption

import org.junit.jupiter.api.Test


class DKSDecryptionTest {

    @Test
    fun testMain(){
        val dksDecryption = mockkObject(DKSDecryption)
        every { dksDecryption } returns "Expected Output"

    }
}
