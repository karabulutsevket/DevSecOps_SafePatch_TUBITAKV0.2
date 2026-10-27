/*
 * SafePatch sandbox test (MIT). Hostile on purpose (ROADMAP.md week 8): it turns the build output
 * directory into a symbolic link to a host directory. The runner reads its reports back from the
 * workspace as the host user, so it must refuse a path that passes through a link.
 */
package demo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

class LinkTest {

    @Test
    void buildOutputBecomesALink() throws Exception {
        Path target = Paths.get("target");
        Files.move(target, Paths.get("target-moved"));
        Files.createSymbolicLink(target, Paths.get("/home"));
    }
}
