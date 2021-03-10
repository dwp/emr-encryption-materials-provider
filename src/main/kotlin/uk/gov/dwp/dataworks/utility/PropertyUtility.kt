package uk.gov.dwp.dataworks.utility

import org.slf4j.LoggerFactory
import java.io.FileInputStream
import java.util.*

object PropertyUtility {

    fun properties(): Map<String, String> =
        try {
            with(Properties()) {
                load(FileInputStream(DKS_PROPERTIES_PATH))
                entries.map { it.key as String to it.value as String }.toMap()
            }
        } catch (e: Exception) {
            logger.error("Exception when loading properties from $DKS_PROPERTIES_PATH", e)
            throw e
        }

    private val DKS_PROPERTIES_PATH = System.getenv("DKS_PROPERTIES_PATH") ?: "/opt/emr/dks.properties"
    private val logger = LoggerFactory.getLogger(PropertyUtility::class.java)
}
