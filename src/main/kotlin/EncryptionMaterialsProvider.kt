package uk.gov.dwp.dataworks

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
import org.springframework.boot.runApplication
import org.springframework.retry.annotation.EnableRetry
import kotlin.system.exitProcess

@SpringBootApplication(exclude = [DataSourceAutoConfiguration::class])
@EnableRetry
open class EncryptionMaterialsProvider

fun main(args: Array<String>) {
    exitProcess(SpringApplication.exit(runApplication<EncryptionMaterialsProvider>(*args)))
}
