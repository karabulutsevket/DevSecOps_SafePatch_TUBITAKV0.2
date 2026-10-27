/*
 * SafePatch sandbox test (MIT). Hostile on purpose (ROADMAP.md week 8): it replaces tracked files
 * inside its own workspace, one with a symbolic link to a path the runner's host also has and one
 * with a named pipe. The runner must report both as changed without opening either: reading the
 * link would read a host file, reading the pipe would block.
 */
package demo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

class TamperTest {

    @Test
    void replaceTrackedFiles() throws Exception {
        Path source = Paths.get("src/main/java/demo/Application.java");
        Files.delete(source);
        Files.createSymbolicLink(source, Paths.get("/etc/hostname"));
        Path test = Paths.get("src/test/java/demo/BehaviorTest.java");
        Files.delete(test);
        assertEquals(0, new ProcessBuilder("mkfifo", test.toString()).start().waitFor());
    }
}
