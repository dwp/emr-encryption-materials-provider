import com.nhaarman.mockitokotlin2.*
import io.kotlintest.shouldThrow
import org.junit.jupiter.api.Test
import uk.gov.dwp.dataworks.utility.RetryUtility.retry
import kotlin.time.ExperimentalTime

@ExperimentalTime
class RetryUtilityTest {

    @Test
    fun testSuccessful() {
        verifyRetries(mock(), 1)
    }

    @Test
    fun testRetriesUntilSuccessful() {
        verifyRetries(mock {
            on { invoke() } doThrow RuntimeException("Error 1") doThrow RuntimeException("Error 2") doAnswer {}
        }, 3)
    }

    @Test
    fun testFailure() {
        verifyRetries(mock {
            on { invoke() } doThrow RuntimeException("Error")
        }, 5, false)
    }

    private fun verifyRetries(f: () -> Unit, functionCalls: Int, succeeds: Boolean = true) {
        if (succeeds) {
            retry(f)
        } else {
            shouldThrow<java.lang.RuntimeException> { retry(f) }
        }
        verify(f, times(functionCalls)).invoke()
    }
}
