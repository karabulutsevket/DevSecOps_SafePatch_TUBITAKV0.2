package demo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class SecurityTest {
    @Test void shellMetacharactersAreLiteral() throws Exception {
        String attack = System.getProperty("os.name").toLowerCase().contains("win") ? "hello & echo INJECTED" : "hello; echo INJECTED";
        assertEquals("echo:" + attack, new DemoService().lookup(attack), "COMMAND_INJECTION_REGRESSION");
    }
}
