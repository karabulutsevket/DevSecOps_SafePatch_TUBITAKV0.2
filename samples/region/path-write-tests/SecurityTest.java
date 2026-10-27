package demo;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
class SecurityTest {
    @Test void cannotSaveOutsideRoot() throws Exception {
        Path parent = Files.createTempDirectory("security"); Path root = Files.createDirectory(parent.resolve("public"));
        System.setProperty("demo.root", root.toString());
        assertThrows(Exception.class, () -> new DemoService().save("../evil.txt", "x"), "PATH_TRAVERSAL_REGRESSION");
        assertFalse(Files.exists(parent.resolve("evil.txt")), "PATH_TRAVERSAL_REGRESSION");
    }
    @Test void cannotSaveThroughNestedDotDot() throws Exception {
        Path parent = Files.createTempDirectory("security"); Path root = Files.createDirectory(parent.resolve("public"));
        System.setProperty("demo.root", root.toString());
        assertThrows(Exception.class, () -> new DemoService().save("sub/../../evil.txt", "x"), "PATH_TRAVERSAL_REGRESSION");
        assertFalse(Files.exists(parent.resolve("evil.txt")), "PATH_TRAVERSAL_REGRESSION");
    }
    @Test void cannotAppendOutsideRoot() throws Exception {
        Path parent = Files.createTempDirectory("security"); Path root = Files.createDirectory(parent.resolve("public"));
        System.setProperty("demo.root", root.toString());
        assertThrows(Exception.class, () -> new DemoService().append("../evil.log", "x"), "PATH_TRAVERSAL_REGRESSION");
        assertFalse(Files.exists(parent.resolve("evil.log")), "PATH_TRAVERSAL_REGRESSION");
    }
}
