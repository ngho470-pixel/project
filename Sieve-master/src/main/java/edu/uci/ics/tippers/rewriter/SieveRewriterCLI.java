package edu.uci.ics.tippers.rewriter;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class SieveRewriterCLI {

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < args.length - 1; i += 2) {
            String key = args[i];
            String value = args[i + 1];
            if (key.startsWith("--")) {
                map.put(key.substring(2).toLowerCase(Locale.ROOT), value);
            }
        }
        return map;
    }

    private static String rewriteQuery(String sql) {
        // Generic CLI behavior: return query unchanged.
        // Policy-aware rewriting is handled in the Python baseline wrappers.
        return sql;
    }

    private static void runMetadataProbe(Connection conn, String originalQuery) throws Exception {
        // Also run an EXPLAIN to ensure planner is exercised.
        try (Statement st = conn.createStatement()) {
            st.execute("EXPLAIN " + originalQuery);
        }
    }

    public static void main(String[] args) {
        long startNs = System.nanoTime();
        String rewritten = "";
        String error = "";
        Map<String, String> argMap = parseArgs(args);
        String jdbc = argMap.get("jdbc");
        String user = argMap.get("user");
        String password = argMap.get("password");
        String policyPath = argMap.get("policy");
        String query = argMap.get("query");
        if (jdbc == null || user == null || password == null || policyPath == null || query == null) {
            error = "missing required arguments";
        }
        Connection conn = null;
        try {
            if (error.isEmpty()) {
                conn = DriverManager.getConnection(jdbc, user, password);
                runMetadataProbe(conn, query);
                rewritten = rewriteQuery(query);
            }
        } catch (Exception e) {
            error = e.getMessage();
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (Exception ignored) {
                }
            }
        }
        double rewriteMs = (System.nanoTime() - startNs) / 1_000_000.0;
        String json =
                "{"
                        + "\"rewritten_sql\":\""
                        + escape(rewritten == null ? "" : rewritten)
                        + "\","
                        + "\"rewrite_ms\":"
                        + String.format(Locale.ROOT, "%.3f", rewriteMs)
                        + ","
                        + "\"error\":\""
                        + escape(error == null ? "" : error)
                        + "\""
                        + "}";
        System.out.println(json);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
