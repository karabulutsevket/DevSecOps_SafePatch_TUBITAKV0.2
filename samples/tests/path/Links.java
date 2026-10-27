package demo;
import java.nio.file.*;
// Test helper: a directory link. Windows without the symbolic-link privilege gets a
// junction instead; toRealPath() resolves both, normalize() resolves neither.
final class Links {
    static void directory(Path link, Path target) throws Exception {
        try {
            Files.createSymbolicLink(link, target);
        } catch (FileSystemException | UnsupportedOperationException e) {
            if (!System.getProperty("os.name").startsWith("Windows")) throw e;
            Process p = new ProcessBuilder("cmd", "/c", "mklink", "/J", link.toString(), target.toString()).redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            if (p.waitFor() != 0 || !Files.isDirectory(link)) throw e;
        }
    }
}
