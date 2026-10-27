package demo;

import java.sql.*;
import java.util.*;

// Deliberately vulnerable synthetic example (development variant: String.format), reference fix. Never use with real data.
public class DemoService {
    public String lookup(String input) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1")) {
            try (Statement init = conn.createStatement()) {
                init.execute("CREATE TABLE IF NOT EXISTS accounts(name VARCHAR PRIMARY KEY)");
                init.execute("MERGE INTO accounts KEY(name) VALUES ('alice'), ('bob')");
            }
            String sql = "SELECT name FROM accounts WHERE name = ?";
            List<String> names = new ArrayList<>();
            try (PreparedStatement statement = conn.prepareStatement(sql)) {
                statement.setString(1, input);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) names.add(rows.getString(1));
                }
            }
            Collections.sort(names);
            return String.join(",", names);
        }
    }
}
