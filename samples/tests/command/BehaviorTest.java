package demo;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class BehaviorTest {
    @Test void echoesHello() throws Exception { assertEquals("echo:hello", new DemoService().lookup("hello")); }
    @Test void echoesWorld() throws Exception { assertEquals("echo:world", new DemoService().lookup("world")); }
}
