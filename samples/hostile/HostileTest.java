/*
 * SafePatch sandbox test (MIT). Hostile on purpose (ROADMAP.md week 8): each test attempts what
 * project code must never be able to do during a build, and passes only if the sandbox stops it.
 * Every attempt stays harmless even if it succeeded: a TCP connection to a public DNS resolver,
 * a marker file, sleeping processes that are destroyed, a memory hog that is killed. The case's
 * descriptor is not a synthetic lab, so the runner refuses to run it outside the Docker sandbox.
 */
package demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class HostileTest {

    private static int run(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        process.getInputStream().readAllBytes();
        return process.waitFor();
    }

    private static void fill(Path file, int megabytes) throws IOException {
        byte[] chunk = new byte[1 << 20];
        try (OutputStream out = Files.newOutputStream(file)) {
            for (int i = 0; i < megabytes; i++) {
                out.write(chunk);
            }
        }
    }

    @Test
    void onlyTheLoopbackInterface() throws Exception {
        List<String> names = new ArrayList<>();
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            names.add(nic.getName());
        }
        assertEquals(List.of("lo"), names);
    }

    @Test
    void noOutboundConnection() {
        // A public resolver, and Docker's API on the default bridge gateway.
        for (InetSocketAddress target : List.of(new InetSocketAddress("1.1.1.1", 53), new InetSocketAddress("172.17.0.1", 2375))) {
            assertThrows(IOException.class, () -> {
                try (Socket socket = new Socket()) {
                    socket.connect(target, 2000);
                }
            }, target.toString());
        }
    }

    @Test
    void noNameResolution() {
        assertThrows(UnknownHostException.class, () -> InetAddress.getByName("example.com"));
    }

    @Test
    void noWritesOutsideTheWorkspace() {
        for (String dir : List.of("/", "/etc", "/m2", "/opt", "/usr/local/bin", "/workspace/..")) {
            Path marker = Paths.get(dir, "safepatch-escape-probe");
            assertThrows(IOException.class, () -> Files.writeString(marker, "escaped"), dir);
        }
    }

    @Test
    void notRootAndWithoutPrivileges() throws Exception {
        String status = Files.readString(Paths.get("/proc/self/status"));
        assertTrue(status.contains("\nUid:\t1000\t"), "uid 1000");
        assertTrue(status.contains("\nCapEff:\t0000000000000000"), "no effective capability");
        assertTrue(status.contains("\nCapBnd:\t0000000000000000"), "no capability to gain");
        assertTrue(status.contains("\nNoNewPrivs:\t1"), "no new privileges");
        assertThrows(IOException.class, () -> Files.readString(Paths.get("/etc/shadow")));
    }

    @Test
    void noMountNoChrootNoNewNamespace() throws Exception {
        assertNotEquals(0, run("mount", "-t", "tmpfs", "none", "/tmp"));
        assertNotEquals(0, run("chroot", "/", "true"));
        assertNotEquals(0, run("unshare", "-Ur", "true"));
    }

    @Test
    void processCountIsBounded() {
        List<Process> started = new ArrayList<>();
        try {
            for (int i = 0; i < 2000; i++) {
                try {
                    started.add(new ProcessBuilder("sleep", "60").start());
                } catch (IOException | OutOfMemoryError limit) {
                    break;
                }
            }
            assertTrue(started.size() < 1024, "started " + started.size() + " processes");
        } finally {
            started.forEach(Process::destroyForcibly);
        }
    }

    @Test
    void memoryIsBounded() throws Exception {
        // `tail` keeps the current line, and /dev/zero never ends one: it only grows.
        Process hog = new ProcessBuilder("tail", "/dev/zero").start();
        boolean ended = hog.waitFor(120, TimeUnit.SECONDS);
        if (!ended) {
            hog.destroyForcibly();
        }
        assertTrue(ended, "still growing after 120 s");
        assertEquals(137, hog.exitValue(), "killed by the memory limit");
    }

    @Test
    void tmpIsBoundedAndNotExecutable() throws Exception {
        Path big = Paths.get("/tmp/safepatch-fill");
        try {
            assertThrows(IOException.class, () -> fill(big, 1100));
        } finally {
            Files.deleteIfExists(big);
        }
        Path tool = Paths.get("/tmp/safepatch-true");
        Files.copy(Paths.get("/bin/true"), tool, StandardCopyOption.REPLACE_EXISTING);
        assertTrue(tool.toFile().setExecutable(true));
        try {
            assertThrows(IOException.class, () -> new ProcessBuilder(tool.toString()).start());
        } finally {
            Files.delete(tool);
        }
    }

    @Test
    void noFileAboveOneGibibyte() throws Exception {
        Path big = Paths.get("target/safepatch-big");
        try {
            assertThrows(IOException.class, () -> fill(big, 1025));
        } finally {
            Files.deleteIfExists(big);
        }
    }
}
