package demo;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
class BehaviorTest {
    @Test void readsAllowedFile() throws Exception {
        Path root = Files.createTempDirectory("allowed");
        Files.writeString(root.resolve("hello.txt"), "hello");
        System.setProperty("demo.root", root.toString());
        assertEquals("hello", new DemoService().lookup("hello.txt"));
    }
    @Test void readsNestedFile() throws Exception {
        Path root = Files.createTempDirectory("allowed"); Files.createDirectory(root.resolve("sub"));
        Files.writeString(root.resolve("sub/hello.txt"), "nested");
        System.setProperty("demo.root", root.toString());
        assertEquals("nested", new DemoService().lookup("sub/hello.txt"));
    }
    @Test void readsThroughLinkedRoot() throws Exception {
        Path base = Files.createTempDirectory("allowed"); Path real = Files.createDirectory(base.resolve("real"));
        Files.writeString(real.resolve("hello.txt"), "linked");
        Path root = base.resolve("root"); Links.directory(root, real);
        System.setProperty("demo.root", root.toString());
        assertEquals("linked", new DemoService().lookup("hello.txt"));
    }
}
