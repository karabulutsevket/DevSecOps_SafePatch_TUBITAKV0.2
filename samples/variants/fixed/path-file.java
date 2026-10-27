package demo;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

// Deliberately vulnerable synthetic example (development variant: java.io.File), reference fix. Root is supplied by trusted runner.
public class DemoService {
    public String lookup(String input) throws Exception {
        java.nio.file.Path root = new File(System.getProperty("demo.root")).toPath().toRealPath();
        java.nio.file.Path target = root.resolve(input).toRealPath();
        if (!target.startsWith(root)) throw new SecurityException("outside root");
        return new String(Files.readAllBytes(target), StandardCharsets.UTF_8);
    }
}
