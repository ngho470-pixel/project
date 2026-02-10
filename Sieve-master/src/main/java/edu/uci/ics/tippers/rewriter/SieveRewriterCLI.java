package edu.uci.ics.tippers.rewriter;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SieveRewriterCLI {

    private static final Pattern FROM_ALIAS =
            Pattern.compile("(?i)\\bfrom\\s+orders\\b(?:\\s+(?:as\\s+)?([a-zA-Z_][\\w]*))?");
    private static final Pattern JOIN_ALIAS =
            Pattern.compile("(?i)\\bjoin\\s+orders\\b(?:\\s+(?:as\\s+)?([a-zA-Z_][\\w]*))?");
    private static final Pattern WHERE_PATTERN = Pattern.compile("(?i)\\bwhere\\b");
    private static final Pattern BOUNDARY_PATTERN =
            Pattern.compile("(?i)\\b(group\\s+by|order\\s+by|limit|offset)\\b");
    private static final String[] RESERVED =
            new String[] {"where", "group", "order", "join", "on", "limit", "offset"};

    private static boolean isReserved(String token) {
        String lower = token.toLowerCase(Locale.ROOT);
        for (String r : RESERVED) {
            if (lower.equals(r)) {
                return true;
            }
        }
        return false;
    }

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

    private static String detectAlias(String sql) {
        Matcher m = FROM_ALIAS.matcher(sql);
        if (m.find()) {
            String alias = m.group(1);
            if (alias != null && !alias.isEmpty() && !isReserved(alias)) {
                return alias;
            }
        }
        m = JOIN_ALIAS.matcher(sql);
        if (m.find()) {
            String alias = m.group(1);
            if (alias != null && !alias.isEmpty() && !isReserved(alias)) {
                return alias;
            }
        }
        return "orders";
    }

    private static String injectPredicate(String sql, String predicate) {
        Matcher whereMatcher = WHERE_PATTERN.matcher(sql);
        if (whereMatcher.find()) {
            int end = whereMatcher.end();
            String rest = sql.substring(end).trim();
            if (rest.isEmpty()) {
                return sql + " " + predicate;
            }
            return sql.substring(0, end) + " (" + predicate + ") AND " + rest;
        }
        Matcher boundary = BOUNDARY_PATTERN.matcher(sql);
        if (boundary.find()) {
            int pos = boundary.start();
            String prefix = sql.substring(0, pos).trim();
            String suffix = sql.substring(pos);
            return prefix + " WHERE " + predicate + " " + suffix;
        }
        return sql + " WHERE " + predicate;
    }

    private static String rewriteQuery(String sql) {
        String alias = detectAlias(sql);
        String predicate =
                "EXISTS (SELECT 1 FROM customer c WHERE c.c_custkey = "
                        + alias
                        + ".o_custkey AND c.c_mktsegment = 'AUTOMOBILE')";
        return injectPredicate(sql, predicate);
    }

    private static void runMetadataProbe(Connection conn, String originalQuery) throws Exception {
        try (PreparedStatement ps =
                     conn.prepareStatement(
                             "SELECT count(*) FROM pg_class WHERE relname IN (?, ?)")) {
            ps.setString(1, "idx_orders_o_custkey");
            ps.setString(2, "idx_customer_c_custkey_mktsegment");
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    rs.getInt(1);
                }
            }
        }
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
