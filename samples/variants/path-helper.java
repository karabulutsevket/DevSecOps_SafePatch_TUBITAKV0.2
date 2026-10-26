package demo;

import java.nio.file.*;

// Deliberately vulnerable synthetic example (development variant: path resolved in a helper). Root is supplied by trusted runner.
public class DemoService {
    public String lookup(String input) throws Exception {
        return Files.readString(resolve(input));
    }

    private Path resolve(String name) {
        return Paths.get(System.getProperty("demo.root"), name);
    }
}
