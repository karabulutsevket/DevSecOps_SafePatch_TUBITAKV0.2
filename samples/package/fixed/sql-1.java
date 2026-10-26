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

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DemoService {

    private static final String DATABASE = "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1";

    public String lookup(String input) throws Exception {
        // some code
        String param = "";
        if (input != null) {
            param = input; // just take the value
        }

        String bar = doSomething(param);

        try (Connection conn = DriverManager.getConnection(DATABASE)) {
            try (Statement init = conn.createStatement()) {
                init.execute("CREATE TABLE IF NOT EXISTS accounts(name VARCHAR PRIMARY KEY)");
                init.execute("MERGE INTO accounts KEY(name) VALUES ('alice'), ('bob')");
            }
            String sql = "SELECT name FROM accounts WHERE name = ?";
            List<String> names = new ArrayList<>();
            try (PreparedStatement statement = conn.prepareStatement(sql)) {
                statement.setString(1, bar);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        names.add(rows.getString(1));
                    }
                }
            }
            Collections.sort(names);
            return String.join(",", names);
        }
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
        String bar = "safe!";
        Map<String, Object> map = new HashMap<>();
        map.put("keyA", "a-Value");
        map.put("keyB", param);
        map.put("keyC", "another-Value");
        bar = (String) map.get("keyB");
        return bar;
    }
}
