package demo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
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
    public String lookup(String input) {
        return label(input);
    }

    public void save(String name, String content) throws IOException {
        File root = new File(System.getProperty("demo.root"));
        File target = new File(root, name);
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IOException("cannot create directory for " + name);
        }
        try (Writer out = new OutputStreamWriter(new FileOutputStream(target), StandardCharsets.UTF_8)) {
            out.write(content);
        }
        remember("saved " + name);
    }

    public void append(String name, String line) throws IOException {
        File root = new File(System.getProperty("demo.root"));
        File target = new File(root, name);
        try (Writer out = new OutputStreamWriter(new FileOutputStream(target, true), StandardCharsets.UTF_8)) {
            out.write(line);
            out.write('\n');
        }
        remember("appended " + name);
    }

//@FILLER_B
}
