package demo;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

// Deliberately vulnerable synthetic subprocess (development variant: String.format), reference fix; no network or real targets.
public class DemoService {
    public String lookup(String input) throws Exception {
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        String java = Path.of(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java").toString();
        Process child = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"), "demo.EchoMain", input).redirectErrorStream(true).start();
        if (!child.waitFor(5, TimeUnit.SECONDS)) { child.destroyForcibly(); throw new IllegalStateException("child timeout"); }
        if (child.exitValue() != 0) throw new IllegalStateException("child failed");
        return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    }
}
