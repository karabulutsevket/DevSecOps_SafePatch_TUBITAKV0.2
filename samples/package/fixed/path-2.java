/*
 * SafePatch development case (MIT).
 *
 * One handler among the many generated handlers of the demo package. The value
 * arrives through lookup(), passes a small helper and reaches one call of the
 * kind this class stands for. Everything here is synthetic: no real data, no
 * network, no real targets. The root folder is supplied by the trusted runner.
 *
 * @created 2026 for the SafePatch L3 development set
 */
package demo;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DemoService {

    public String lookup(String input) throws Exception {
        // some code
        String param = "";
        if (input != null) {
            param = input;
        }

        String bar = doSomething(param);

        java.nio.file.Path base = new File(System.getProperty("demo.root")).toPath().toRealPath();
        java.nio.file.Path fileTarget = base.resolve(bar).toRealPath();
        if (!fileTarget.startsWith(base)) {
            throw new SecurityException("outside root");
        }
        byte[] content = Files.readAllBytes(fileTarget);
        return new String(content, StandardCharsets.UTF_8);
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
        String bar = "alsosafe";
        if (param != null) {
            List<String> valuesList = new ArrayList<>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");

            valuesList.remove(0); // remove the 1st safe value

            bar = valuesList.get(0); // get the param value
        }
        return bar;
    }
}
