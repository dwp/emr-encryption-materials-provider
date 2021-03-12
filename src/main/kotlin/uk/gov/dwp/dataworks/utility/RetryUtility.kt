package uk.gov.dwp.dataworks.utility
import org.slf4j.LoggerFactory
import uk.gov.dwp.dataworks.utility.PropertyUtility.properties
import kotlin.time.ExperimentalTime

@ExperimentalTime
object RetryUtility {

    fun <T> retry(f: () -> T): T {

        fun go(attempts: Int): T {
            return try {
                f()
            } catch (e: Exception) {
                logFailedAttempt(attempts, e)
                Thread.sleep(attemptDelay(attempts))
                if (attempts > maxAttempts - 1) {
                    throw e
                }
                go(attempts + 1)
            }
        }

        return go(1)
    }


    private fun attemptDelay(attempt: Int): Long =
        if (attempt == 0) {
            initialBackoff
        } else {
            (initialBackoff * attempt * backoffMultiplier.toFloat()).toLong()
        }


    private val initialBackoff: Long by lazy {
        retryProperty(RETRY_INITIAL_BACKOFF, "10000").toLong()
    }

    private val backoffMultiplier: Long by lazy {
        retryProperty(RETRY_BACKOFF_MULTIPLIER, "2").toLong()
    }

    private val maxAttempts: Int by lazy {
        retryProperty(RETRY_MAX_ATTEMPTS, "5").toInt()
    }

    private fun retryProperty(name: String, default: String): String =
        (properties[name] ?: System.getProperty(name, default))

    private val properties: Map<String, String> by lazy {
        try {
            properties()
        } catch (e: Exception) {
            mapOf()
        }
    }

    private fun logFailedAttempt(attempts: Int, e: Exception) {
        logger.warn("Retryable function failed", "attempt_number" to "$attempts",
            "initial_backoff" to "$initialBackoff",
            "backoff_multiplier" to "$backoffMultiplier",
            "max_attempts" to "$maxAttempts",
            "retry_delay" to "${attemptDelay(attempts)}",
            "error_message" to "${e.message}")
    }

    private const val RETRY_INITIAL_BACKOFF = "retry.initial.backoff"
    private const val RETRY_BACKOFF_MULTIPLIER = "retry.backoff.multiplier"
    private const val RETRY_MAX_ATTEMPTS = "retry.max.attempts"

    private val logger = LoggerFactory.getLogger(RetryUtility::class.java)
}
