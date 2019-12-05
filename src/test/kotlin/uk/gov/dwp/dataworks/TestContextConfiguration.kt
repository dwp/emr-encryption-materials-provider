package uk.gov.dwp.dataworks

import org.mockito.Mockito
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import uk.gov.dwp.dataworks.dks.providers.HttpClientProvider

@Configuration
open class TestContextConfiguration {

    @Bean
    @Profile("unitTest")
    open fun httpClientProvider() = Mockito.mock(HttpClientProvider::class.java)!!

}
