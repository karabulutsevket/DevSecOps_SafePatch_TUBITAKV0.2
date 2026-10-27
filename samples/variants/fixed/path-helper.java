package demo;

import java.nio.file.*;

// Deliberately vulnerable synthetic example (development variant: path resolved in a helper), reference fix. Root is supplied by trusted runner.
public class DemoService {
    public String lookup(String input) throws Exception {
        return Files.readString(resolve(input));
    }

    private Path resolve(String name) throws java.io.IOException {
        Path root = Paths.get(System.getProperty("demo.root")).toRealPath();
        Path target = root.resolve(name).toRealPath();
        if (!target.startsWith(root)) throw new SecurityException("outside root");
        return target;
    }
}
