package demo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class SecurityTest {
    @Test void injectionMustNotReturnAccounts() throws Exception {
        assertEquals("", new DemoService().lookup("x' OR '1'='1"), "SQL_INJECTION_REGRESSION");
    }
}
