package demo;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

// Deliberately vulnerable synthetic subprocess; no network or real targets.
public class DemoService {
    public String lookup(String input) throws Exception {
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        String java = Path.of(System.getProperty("java.home"), "bin", windows ? "java.exe" : "java").toString();
        String shell = windows ? "cmd.exe" : "/bin/sh";
        String flag = windows ? "/c" : "-c";
        String command = "echo echo:" + input;
        Process child = new ProcessBuilder(shell, flag, command).redirectErrorStream(true).start();
        if (!child.waitFor(5, TimeUnit.SECONDS)) { child.destroyForcibly(); throw new IllegalStateException("child timeout"); }
        if (child.exitValue() != 0) throw new IllegalStateException("child failed");
        return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    }
}
