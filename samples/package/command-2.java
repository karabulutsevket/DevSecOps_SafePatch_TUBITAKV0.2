/*
 * SafePatch development case (MIT).
 *
 * One handler among the many generated handlers of the demo package. The value
 * arrives through lookup(), passes a small helper and reaches one call of the
 * kind this class stands for. Everything here is synthetic: no real data, no
 * network, no real targets.
 *
 * @created 2026 for the SafePatch L3 development set
 */
package demo;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.Map;

public class DemoService {

    private static final String VARIABLE = "SAFEPATCH_VALUE";

    public String lookup(String input) throws Exception {
        // some code
        String param = "";
        if (input != null) {
            param = input; // just take the value
        }

        String bar = doSomething(param);

        // The shell reads the value from its environment.
        boolean windows = System.getProperty("os.name").toLowerCase().contains("win");
        String[] shell = windows
                ? new String[] {"cmd.exe", "/c", "echo echo:%" + VARIABLE + "%"}
                : new String[] {"/bin/sh", "-c", "eval \"echo echo:$" + VARIABLE + "\""};
        ProcessBuilder builder = new ProcessBuilder(shell).redirectErrorStream(true);
        builder.environment().put(VARIABLE, bar);
        Process child = builder.start();
        if (!child.waitFor(5, TimeUnit.SECONDS)) {
            child.destroyForcibly();
            throw new IllegalStateException("child timeout");
        }
        if (child.exitValue() != 0) {
            throw new IllegalStateException("child failed");
        }
        return new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
    }

    /** Entry point the package's dispatcher calls with the request's values; lookup() holds the work. */
    public void serve(Map<String, String> request, StringBuilder response) {
        response.append("<!DOCTYPE html>\n<html>\n<body>\n<p>");
        String value = request.getOrDefault("DemoService", "");
        try {
            response.append("Result: ").append(escape(lookup(value)));
        } catch (Exception e) {
            response.append("Error processing request.");
        }
        response.append("</p>\n</body>\n</html>");
    }

    private static String escape(String text) {
        StringBuilder out = new StringBuilder();
        for (char c : text.toCharArray()) {
            switch (c) {
                case '<':
                    out.append("&lt;");
                    break;
                case '>':
                    out.append("&gt;");
                    break;
                case '&':
                    out.append("&amp;");
                    break;
                case '"':
                    out.append("&quot;");
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    private static String doSomething(String param) {
        String bar;

        // Simple ? condition that assigns the value to bar on a false condition
        int num = 106;
        bar = (7 * 42) - num > 200 ? "This should never happen" : param;

        return bar;
    }
}
