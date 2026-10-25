package demo;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

// Deliberately vulnerable synthetic example (region-mode development case). Root is supplied by trusted runner.
public class DemoService {
//@FILLER_A
    public String lookup(String input) throws IOException {
        File root = new File(System.getProperty("demo.root"));
        File target = new File(root, input);
        remember("read " + input);
        return new String(Files.readAllBytes(target.toPath()), StandardCharsets.UTF_8);
    }

//@FILLER_B
}
