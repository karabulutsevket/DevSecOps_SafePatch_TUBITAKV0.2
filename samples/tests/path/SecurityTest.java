package demo;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import static org.junit.jupiter.api.Assertions.*;
class SecurityTest {
    @Test void cannotReadParentSecret() throws Exception {
        Path parent = Files.createTempDirectory("security"); Path root = Files.createDirectory(parent.resolve("public"));
        Files.writeString(parent.resolve("secret.txt"), "PRIVATE"); System.setProperty("demo.root", root.toString());
        assertThrows(Exception.class, () -> new DemoService().lookup("../secret.txt"), "PATH_TRAVERSAL_REGRESSION");
    }
    @Test void cannotReadAbsolutePathOutsideRoot() throws Exception {
        Path parent = Files.createTempDirectory("security"); Path root = Files.createDirectory(parent.resolve("public"));
        Path secret = Files.writeString(parent.resolve("secret.txt"), "PRIVATE"); System.setProperty("demo.root", root.toString());
        assertThrows(Exception.class, () -> new DemoService().lookup(secret.toAbsolutePath().toString()), "PATH_TRAVERSAL_REGRESSION");
    }
    @Test void cannotEscapeThroughLinkInsideRoot() throws Exception {
        Path parent = Files.createTempDirectory("security"); Path root = Files.createDirectory(parent.resolve("public"));
        Path outside = Files.createDirectory(parent.resolve("outside")); Files.writeString(outside.resolve("secret.txt"), "PRIVATE");
        Links.directory(root.resolve("escape"), outside); System.setProperty("demo.root", root.toString());
        assertThrows(Exception.class, () -> new DemoService().lookup("escape/secret.txt"), "PATH_TRAVERSAL_REGRESSION");
    }
}
