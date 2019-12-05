package uk.gov.dwp.dataworks.dks.providers

import org.apache.http.impl.client.CloseableHttpClient

interface HttpClientProvider {
    fun client(): CloseableHttpClient
}
