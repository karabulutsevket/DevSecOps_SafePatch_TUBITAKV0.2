package demo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

// Deliberately vulnerable synthetic subprocess (region-mode development case); no network or real targets.
public class DemoService {
//@FILLER_A
    public String lookup(String input) throws IOException, InterruptedException {
        boolean windows = System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
        String java = Path.of(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java").toString();
        String shell = windows ? "cmd.exe" : "/bin/sh";
        String flag = windows ? "/c" : "-c";
        String command = "echo echo:" + input;
        Process child = new ProcessBuilder(shell, flag, command).redirectErrorStream(true).start();
        if (!child.waitFor(5, TimeUnit.SECONDS)) {
            child.destroyForcibly();
            throw new IllegalStateException("child timeout");
        }
        if (child.exitValue() != 0) {
            throw new IllegalStateException("child failed");
        }
        remember("ran " + java.length());
        return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    }

//@FILLER_B
}
