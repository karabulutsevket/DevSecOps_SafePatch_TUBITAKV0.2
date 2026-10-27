package demo;

import java.sql.*;
import java.util.*;

// Deliberately vulnerable synthetic example (development variant: query built in a helper). Never use with real data.
public class DemoService {
    public String lookup(String input) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1")) {
            try (Statement init = conn.createStatement()) {
                init.execute("CREATE TABLE IF NOT EXISTS accounts(name VARCHAR PRIMARY KEY)");
                init.execute("MERGE INTO accounts KEY(name) VALUES ('alice'), ('bob')");
            }
            return String.join(",", names(conn, input));
        }
    }

    private List<String> names(Connection conn, String name) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Statement statement = conn.createStatement();
             ResultSet rows = statement.executeQuery("SELECT name FROM accounts WHERE name = '" + name + "'")) {
            while (rows.next()) names.add(rows.getString(1));
        }
        Collections.sort(names);
        return names;
    }
}
