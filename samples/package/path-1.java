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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class DemoService {

    private static final String ROOT_PROPERTY = "demo.root";

    public String lookup(String input) throws Exception {
        // some code
        String param = "";
        if (input != null) {
            param = input; // just take the value
        }

        String bar = doSomething(param);

        Path root = Path.of(System.getProperty(ROOT_PROPERTY));
        Path target = root.resolve(bar);
        String text = Files.readString(target);
        return text;
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

        // Simple if statement that assigns a constant to bar on a true condition
        int num = 86;
        if ((7 * 18) - num > 200) {
            bar = "This_should_never_happen";
        } else {
            bar = param;
        }

        return bar;
    }
}
