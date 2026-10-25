package demo;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
class BehaviorTest {
    @Test void savesFile() throws Exception {
        Path root = Files.createTempDirectory("allowed");
        System.setProperty("demo.root", root.toString());
        new DemoService().save("hello.txt", "hello");
        assertEquals("hello", Files.readString(root.resolve("hello.txt")));
    }
    @Test void savesNestedFileCreatingDirectories() throws Exception {
        Path root = Files.createTempDirectory("allowed");
        System.setProperty("demo.root", root.toString());
        new DemoService().save("notes/2026/today.txt", "nested");
        assertEquals("nested", Files.readString(root.resolve("notes/2026/today.txt")));
    }
    @Test void appendsLines() throws Exception {
        Path root = Files.createTempDirectory("allowed");
        System.setProperty("demo.root", root.toString());
        DemoService service = new DemoService();
        service.save("log.txt", "");
        service.append("log.txt", "one");
        service.append("log.txt", "two");
        assertEquals("one\ntwo\n", Files.readString(root.resolve("log.txt")));
    }
    @Test void savesThroughLinkedRoot() throws Exception {
        Path base = Files.createTempDirectory("allowed"); Path real = Files.createDirectory(base.resolve("real"));
        Path root = base.resolve("root"); Links.directory(root, real);
        System.setProperty("demo.root", root.toString());
        new DemoService().save("sub/linked.txt", "linked");
        assertEquals("linked", Files.readString(real.resolve("sub/linked.txt")));
    }
}
