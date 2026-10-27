package demo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class BehaviorTest {
    @Test void knownAccount() throws Exception { assertEquals("alice", new DemoService().lookup("alice")); }
    @Test void secondAccount() throws Exception { assertEquals("bob", new DemoService().lookup("bob")); }
    @Test void unknownAccount() throws Exception { assertEquals("", new DemoService().lookup("nobody")); }
}
