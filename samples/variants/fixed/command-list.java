package demo;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

// Deliberately vulnerable synthetic subprocess (development variant: argv list), reference fix; no network or real targets.
public class DemoService {
    public String lookup(String input) throws Exception {
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        String java = Path.of(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java").toString();
        List<String> argv = new ArrayList<>();
        argv.add(java);
        argv.add("-cp");
        argv.add(System.getProperty("java.class.path"));
        argv.add("demo.EchoMain");
        argv.add(input);
        Process child = new ProcessBuilder(argv).redirectErrorStream(true).start();
        if (!child.waitFor(5, TimeUnit.SECONDS)) { child.destroyForcibly(); throw new IllegalStateException("child timeout"); }
        if (child.exitValue() != 0) throw new IllegalStateException("child failed");
        return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    }
}
