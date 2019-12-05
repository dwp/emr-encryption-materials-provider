package app.services.impl

import app.services.KeyService
import org.springframework.context.annotation.Profile
import org.springframework.stereotype.Service
import uk.gov.dwp.dataworks.dks.domain.DataKeyResult

@Service
@Profile("phoneyDataKeyService")
class PhoneyKeyService : KeyService {

    override fun batchDataKey() = dataKey

    private val dataKey =
        DataKeyResult("38db138e-5b56-4557-9295-6d4fcbf97efe",
            "6mwpljlWP6PRkmlpZG8/tA==",
            "AQIDAHiDZm7dsImftTfAGQhiuj+6YBT6kuD9jOcAaAq8C3vEJAEE4n2vGGRdcLE5HSPnvubSAAAAbjBsBgkqhkiG9w0BBwagXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMAEEUtsZYTMkzqiWDAgEQgCuN79GkLdP+R0q4z0By8nIrDZSYazOVnf3WLX4mIvhXDygR9yVGKZI6j+CD")

    override fun decryptKey(encryptionKeyId: String, encryptedKey: String) = "czMQLgW/OrzBZwFV9u4EBA=="
}
