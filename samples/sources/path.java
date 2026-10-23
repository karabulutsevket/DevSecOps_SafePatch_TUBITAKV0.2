package demo;

import java.nio.file.*;

// Deliberately vulnerable synthetic example. Root is supplied by trusted runner.
public class DemoService {
    public String lookup(String input) throws Exception {
        Path root = Path.of(System.getProperty("demo.root"));
        Path target = root.resolve(input);
        return Files.readString(target);
    }
}
