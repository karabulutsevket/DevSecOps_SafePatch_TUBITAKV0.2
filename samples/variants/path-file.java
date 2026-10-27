package demo;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

// Deliberately vulnerable synthetic example (development variant: java.io.File). Root is supplied by trusted runner.
public class DemoService {
    public String lookup(String input) throws Exception {
        File root = new File(System.getProperty("demo.root"));
        File target = new File(root, input);
        return new String(Files.readAllBytes(target.toPath()), StandardCharsets.UTF_8);
    }
}
