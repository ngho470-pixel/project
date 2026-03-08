package edu.uci.ics.tippers.rewriter;

import edu.uci.ics.tippers.common.AttributeType;
import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.model.guard.GuardExp;
import edu.uci.ics.tippers.model.guard.SelectGuard;
import edu.uci.ics.tippers.model.policy.BEExpression;
import edu.uci.ics.tippers.model.policy.BEPolicy;
import edu.uci.ics.tippers.model.policy.ObjectCondition;
import edu.uci.ics.tippers.model.policy.Operation;

import java.io.BufferedReader;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SieveRewriterCLI {

    private static final String DEMO_QUERIER = "1";
    private static final String DEMO_PURPOSE = "cf_demo";
    private static final String DEMO_ACTION = "allow";

    private static final Pattern POLICY_ID_PREFIX =
            Pattern.compile("^\\s*(\\d+)\\s*(?:[.:]\\s*|\\s+)(.*)$");
    private static final Pattern ATOM_PATTERN =
            Pattern.compile("^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*(<=|>=|=|<|>)\\s*(.+?)\\s*$");
    private static final Pattern IDENT_PATTERN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*$");

    private enum TokType {
        LPAREN,
        RPAREN,
        AND,
        OR,
        ATOM
    }

    private static final class Token {
        final TokType type;
        final String text;

        Token(TokType type, String text) {
            this.type = type;
            this.text = text;
        }
    }

    private static abstract class Expr {}

    private static final class AtomExpr extends Expr {
        final String atom;

        AtomExpr(String atom) {
            this.atom = atom;
        }
    }

    private static final class AndExpr extends Expr {
        final Expr left;
        final Expr right;

        AndExpr(Expr left, Expr right) {
            this.left = left;
            this.right = right;
        }
    }

    private static final class OrExpr extends Expr {
        final Expr left;
        final Expr right;

        OrExpr(Expr left, Expr right) {
            this.left = left;
            this.right = right;
        }
    }

    private static final class Parser {
        private final List<Token> tokens;
        private int pos;

        Parser(List<Token> tokens) {
            this.tokens = tokens;
            this.pos = 0;
        }

        private Token peek() {
            if (pos >= tokens.size()) {
                return null;
            }
            return tokens.get(pos);
        }

        private Token consume() {
            Token t = peek();
            if (t == null) {
                throw new IllegalArgumentException("Unexpected end of expression");
            }
            pos += 1;
            return t;
        }

        private Token expect(TokType t) {
            Token got = consume();
            if (got.type != t) {
                throw new IllegalArgumentException("Expected " + t + " but got " + got.type);
            }
            return got;
        }

        Expr parse() {
            Expr out = parseOr();
            if (peek() != null) {
                throw new IllegalArgumentException("Unexpected token: " + peek().text);
            }
            return out;
        }

        private Expr parseOr() {
            Expr left = parseAnd();
            while (peek() != null && peek().type == TokType.OR) {
                consume();
                Expr right = parseAnd();
                left = new OrExpr(left, right);
            }
            return left;
        }

        private Expr parseAnd() {
            Expr left = parsePrimary();
            while (peek() != null && peek().type == TokType.AND) {
                consume();
                Expr right = parsePrimary();
                left = new AndExpr(left, right);
            }
            return left;
        }

        private Expr parsePrimary() {
            Token t = peek();
            if (t == null) {
                throw new IllegalArgumentException("Unexpected end of expression");
            }
            if (t.type == TokType.LPAREN) {
                consume();
                Expr inner = parseOr();
                expect(TokType.RPAREN);
                return inner;
            }
            if (t.type == TokType.ATOM) {
                consume();
                return new AtomExpr(t.text);
            }
            throw new IllegalArgumentException("Unexpected token: " + t.text);
        }
    }

    private static final class PolicyEntry {
        final int policyId;
        final String targetTable;
        final String expression;

        PolicyEntry(int policyId, String targetTable, String expression) {
            this.policyId = policyId;
            this.targetTable = targetTable;
            this.expression = expression;
        }
    }

    private static final class AtomParts {
        final String attribute;
        final String operator;
        final String value;
        final String type;

        AtomParts(String attribute, String operator, String value, String type) {
            this.attribute = attribute;
            this.operator = operator;
            this.value = value;
            this.type = type;
        }
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

    private static boolean isWordBoundary(char ch) {
        return !(Character.isLetterOrDigit(ch) || ch == '_');
    }

    private static boolean matchesWord(String s, int i, String word) {
        int end = i + word.length();
        if (end > s.length()) {
            return false;
        }
        if (!s.regionMatches(true, i, word, 0, word.length())) {
            return false;
        }
        char prev = (i > 0) ? s.charAt(i - 1) : ' ';
        char next = (end < s.length()) ? s.charAt(end) : ' ';
        return isWordBoundary(prev) && isWordBoundary(next);
    }

    private static List<Token> tokenizeExpr(String expr) {
        List<Token> out = new ArrayList<>();
        int i = 0;
        while (i < expr.length()) {
            char ch = expr.charAt(i);
            if (Character.isWhitespace(ch)) {
                i += 1;
                continue;
            }
            if (ch == '(') {
                out.add(new Token(TokType.LPAREN, "("));
                i += 1;
                continue;
            }
            if (ch == ')') {
                out.add(new Token(TokType.RPAREN, ")"));
                i += 1;
                continue;
            }
            if (matchesWord(expr, i, "AND")) {
                out.add(new Token(TokType.AND, "AND"));
                i += 3;
                continue;
            }
            if (matchesWord(expr, i, "OR")) {
                out.add(new Token(TokType.OR, "OR"));
                i += 2;
                continue;
            }
            int start = i;
            while (i < expr.length()) {
                char c = expr.charAt(i);
                if (c == '(' || c == ')') {
                    break;
                }
                if (matchesWord(expr, i, "AND") || matchesWord(expr, i, "OR")) {
                    break;
                }
                i += 1;
            }
            String atom = expr.substring(start, i).trim();
            if (!atom.isEmpty()) {
                out.add(new Token(TokType.ATOM, atom));
            }
        }
        return out;
    }

    private static Expr parseExpr(String expr) {
        Parser p = new Parser(tokenizeExpr(expr));
        return p.parse();
    }

    private static List<List<String>> toDNF(Expr expr) {
        if (expr instanceof AtomExpr) {
            List<List<String>> out = new ArrayList<>();
            List<String> one = new ArrayList<>();
            one.add(((AtomExpr) expr).atom);
            out.add(one);
            return out;
        }
        if (expr instanceof OrExpr) {
            OrExpr or = (OrExpr) expr;
            List<List<String>> out = new ArrayList<>(toDNF(or.left));
            out.addAll(toDNF(or.right));
            return out;
        }
        if (expr instanceof AndExpr) {
            AndExpr and = (AndExpr) expr;
            return crossTerms(toDNF(and.left), toDNF(and.right));
        }
        throw new IllegalArgumentException("Unknown expression node");
    }

    private static List<List<String>> crossTerms(List<List<String>> a, List<List<String>> b) {
        List<List<String>> out = new ArrayList<>();
        for (List<String> x : a) {
            for (List<String> y : b) {
                List<String> merged = new ArrayList<>(x.size() + y.size());
                merged.addAll(x);
                merged.addAll(y);
                out.add(merged);
            }
        }
        return out;
    }

    private static PolicyEntry parsePolicyLine(String line) {
        String s = line.trim();
        Matcher m = POLICY_ID_PREFIX.matcher(s);
        if (!m.matches()) {
            throw new IllegalArgumentException("Policy id missing in line: " + line);
        }
        int policyId = Integer.parseInt(m.group(1));
        String rest = m.group(2).trim();
        int colon = rest.indexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("Policy line missing ':' separator: " + line);
        }
        String target = rest.substring(0, colon).trim().toLowerCase(Locale.ROOT);
        String expr = rest.substring(colon + 1).trim();
        if (target.isEmpty() || expr.isEmpty()) {
            throw new IllegalArgumentException("Malformed policy line: " + line);
        }
        if (!IDENT_PATTERN.matcher(target).matches()) {
            throw new IllegalArgumentException("Unsupported target table identifier: " + target);
        }
        return new PolicyEntry(policyId, target, expr);
    }

    private static List<PolicyEntry> readPolicyEntries(String policyPath) throws Exception {
        List<PolicyEntry> entries = new ArrayList<>();
        try (BufferedReader br = Files.newBufferedReader(Paths.get(policyPath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String s = line.trim();
                if (s.isEmpty() || s.startsWith("#")) {
                    continue;
                }
                entries.add(parsePolicyLine(s));
            }
        }
        return entries;
    }

    private static String extractSingleTargetTable(List<PolicyEntry> entries) {
        Set<String> targets = new HashSet<>();
        for (PolicyEntry pe : entries) {
            targets.add(pe.targetTable);
        }
        if (targets.isEmpty()) {
            return "";
        }
        if (targets.size() != 1) {
            throw new IllegalArgumentException(
                    "Current Sieve demo ingest expects a single target table; found: " + targets);
        }
        return targets.iterator().next();
    }

    private static List<List<String>> composeAllowTermsOddEven(List<PolicyEntry> entries) {
        List<List<String>> oddTerms = new ArrayList<>();
        List<List<String>> evenCombined = new ArrayList<>();
        evenCombined.add(new ArrayList<String>());

        for (PolicyEntry pe : entries) {
            List<List<String>> terms = toDNF(parseExpr(pe.expression));
            if ((pe.policyId % 2) == 1) {
                oddTerms.addAll(terms);
            } else {
                evenCombined = crossTerms(evenCombined, terms);
            }
        }
        if (oddTerms.isEmpty()) {
            return new ArrayList<>();
        }

        List<List<String>> finalTerms = crossTerms(oddTerms, evenCombined);
        List<List<String>> normalized = new ArrayList<>();
        for (List<String> term : finalTerms) {
            LinkedHashSet<String> dedup = new LinkedHashSet<>();
            for (String atom : term) {
                String t = atom.trim();
                if (!t.isEmpty()) {
                    dedup.add(t);
                }
            }
            normalized.add(new ArrayList<>(dedup));
        }
        return normalized;
    }

    private static void ensurePolicyStorageTables(Connection conn) throws Exception {
        try (Statement st = conn.createStatement()) {
            st.execute(
                    "CREATE TABLE IF NOT EXISTS USER_POLICY ("
                            + "id varchar(255) PRIMARY KEY,"
                            + "querier varchar(255) NOT NULL,"
                            + "purpose varchar(255) NOT NULL,"
                            + "enforcement_action varchar(255),"
                            + "inserted_at timestamp NOT NULL"
                            + ")");
            st.execute(
                    "CREATE TABLE IF NOT EXISTS USER_POLICY_OBJECT_CONDITION ("
                            + "id bigserial PRIMARY KEY,"
                            + "policy_id varchar(255) NOT NULL REFERENCES USER_POLICY(id) ON DELETE CASCADE,"
                            + "attribute varchar(255) NOT NULL,"
                            + "attribute_type varchar(255) NOT NULL,"
                            + "operator varchar(255) NOT NULL,"
                            + "comp_value varchar(255)"
                            + ")");
            st.execute(
                    "CREATE INDEX IF NOT EXISTS idx_user_policy_object_condition_policy_id "
                            + "ON USER_POLICY_OBJECT_CONDITION(policy_id)");
        }
    }

    private static void clearDemoPolicies(Connection conn) throws Exception {
        try (PreparedStatement ps =
                        conn.prepareStatement("DELETE FROM USER_POLICY WHERE querier = ? AND purpose = ?")) {
            ps.setString(1, DEMO_QUERIER);
            ps.setString(2, DEMO_PURPOSE);
            ps.executeUpdate();
        }
    }

    private static AtomParts parseAtom(String atom) {
        Matcher m = ATOM_PATTERN.matcher(atom);
        if (!m.matches()) {
            throw new IllegalArgumentException("Unsupported atom in policy term: " + atom);
        }
        String attr = m.group(1).trim();
        String op = m.group(2).trim();
        String rawValue = m.group(3).trim();
        if (attr.contains(".")) {
            throw new IllegalArgumentException(
                    "Qualified columns are not supported in this Sieve ingest path: " + atom);
        }

        String value;
        String type;
        if (rawValue.length() >= 2 && rawValue.startsWith("'") && rawValue.endsWith("'")) {
            value = rawValue.substring(1, rawValue.length() - 1).replace("''", "'");
            type = "STRING";
        } else if (rawValue.matches("-?\\d+")) {
            value = rawValue;
            type = "INTEGER";
        } else if (rawValue.matches("-?\\d+\\.\\d+")) {
            value = rawValue;
            type = "DOUBLE";
        } else {
            value = rawValue;
            type = "STRING";
        }
        return new AtomParts(attr, op, value, type);
    }

    private static int ingestPoliciesWithOddEvenDemoContext(Connection conn, List<List<String>> terms) throws Exception {
        ensurePolicyStorageTables(conn);
        clearDemoPolicies(conn);
        if (terms.isEmpty()) {
            return 0;
        }

        long stamp = System.currentTimeMillis();
        Timestamp now = new Timestamp(stamp);
        try (PreparedStatement pol =
                        conn.prepareStatement(
                                "INSERT INTO USER_POLICY(id, querier, purpose, enforcement_action, inserted_at) "
                                        + "VALUES (?, ?, ?, ?, ?)");
                PreparedStatement oc =
                        conn.prepareStatement(
                                "INSERT INTO USER_POLICY_OBJECT_CONDITION(policy_id, attribute, attribute_type, operator, comp_value) "
                                        + "VALUES (?, ?, ?, ?, ?)")) {
            int idx = 0;
            for (List<String> term : terms) {
                String pid = "cf_demo_" + stamp + "_" + idx;
                pol.setString(1, pid);
                pol.setString(2, DEMO_QUERIER);
                pol.setString(3, DEMO_PURPOSE);
                pol.setString(4, DEMO_ACTION);
                pol.setTimestamp(5, now);
                pol.addBatch();

                for (String atom : term) {
                    AtomParts ap = parseAtom(atom);
                    for (int k = 0; k < 2; k++) {
                        oc.setString(1, pid);
                        oc.setString(2, ap.attribute);
                        oc.setString(3, ap.type);
                        oc.setString(4, ap.operator);
                        oc.setString(5, ap.value);
                        oc.addBatch();
                    }
                }
                idx += 1;
            }
            pol.executeBatch();
            oc.executeBatch();
            return terms.size();
        }
    }

    private static Operation toOperation(String op) {
        if ("=".equals(op)) {
            return Operation.EQ;
        }
        if (">=".equals(op)) {
            return Operation.GTE;
        }
        if ("<=".equals(op)) {
            return Operation.LTE;
        }
        if (">".equals(op)) {
            return Operation.GT;
        }
        if ("<".equals(op)) {
            return Operation.LT;
        }
        throw new IllegalArgumentException("Unsupported operator: " + op);
    }

    private static AttributeType toAttributeType(AtomParts ap) {
        if ("INTEGER".equals(ap.type)) {
            return AttributeType.INTEGER;
        }
        if ("DOUBLE".equals(ap.type)) {
            return AttributeType.DOUBLE;
        }
        if (ap.value.matches("\\d{4}-\\d{2}-\\d{2}")) {
            return AttributeType.DATE;
        }
        if (ap.value.matches("\\d{2}:\\d{2}(:\\d{2})?")) {
            return AttributeType.TIME;
        }
        return AttributeType.STRING;
    }

    private static List<BEPolicy> buildAllowPoliciesFromTerms(List<List<String>> terms) {
        List<BEPolicy> out = new ArrayList<>();
        long stamp = System.currentTimeMillis();
        Timestamp now = new Timestamp(stamp);
        int pidx = 0;

        for (List<String> term : terms) {
            String pid = "cf_demo_be_" + stamp + "_" + pidx;
            List<ObjectCondition> conditions = new ArrayList<>();
            int cidx = 0;
            for (String atom : term) {
                AtomParts ap = parseAtom(atom);
                AttributeType at = toAttributeType(ap);
                Operation op = toOperation(ap.operator);
                ObjectCondition oc = new ObjectCondition(pid, ap.attribute, at, ap.value, op);
                oc.setPolicy_id(pid + "_" + cidx);
                conditions.add(oc);
                cidx += 1;
            }
            BEPolicy p = new BEPolicy(pid, conditions, new ArrayList<>(), DEMO_PURPOSE, DEMO_ACTION, now);
            out.add(p);
            pidx += 1;
        }
        return out;
    }

    private static long countTableRows(Connection conn, String tableName) throws Exception {
        try (Statement st = conn.createStatement();
                ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM " + tableName)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private static void setStaticField(Class<?> cls, String fieldName, Object value) throws Exception {
        Field f = cls.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(null, value);
    }

    private static void initializePolicyConstantsForSieve(
            Connection conn,
            String targetTable,
            List<BEPolicy> allowPolicies)
            throws Exception {
        LinkedHashSet<String> attrs = new LinkedHashSet<>();
        LinkedHashSet<String> rangeAttrs = new LinkedHashSet<>();
        for (BEPolicy p : allowPolicies) {
            for (ObjectCondition oc : p.getObject_conditions()) {
                attrs.add(oc.getAttribute());
                Set<Operation> ops = new HashSet<>();
                for (int i = 0; i < oc.getBooleanPredicates().size(); i++) {
                    ops.add(oc.getBooleanPredicates().get(i).getOperator());
                }
                if (ops.contains(Operation.GTE)
                        || ops.contains(Operation.GT)
                        || ops.contains(Operation.LTE)
                        || ops.contains(Operation.LT)) {
                    rangeAttrs.add(oc.getAttribute());
                }
            }
        }
        if (attrs.isEmpty()) {
            attrs.add("id");
        }

        PolicyConstants.DBMS_CHOICE = PolicyConstants.PGSQL_DBMS;
        PolicyConstants.DBMS_LOCATION = "dynamic";
        PolicyConstants.DBMS_CREDENTIALS = "dynamic";
        PolicyConstants.TABLE_NAME = targetTable;
        PolicyConstants.DATE_FORMAT = "yyyy-MM-dd";
        PolicyConstants.TIME_FORMAT = "HH:mm:ss";
        PolicyConstants.TIMESTAMP_FORMAT = "yyyy-MM-dd HH:mm:ss";

        PolicyConstants.SELECT_ALL = "Select * from " + targetTable + " ";
        PolicyConstants.SELECT_ALL_WHERE = "Select * from " + targetTable + " where ";

        PolicyConstants.INFINTIY = 10_000_000_000_000L;
        PolicyConstants.BATCH_SIZE_INSERTION = 50_000;
        PolicyConstants.MAX_DURATION = Duration.ofMillis(30_000);
        PolicyConstants.IO_BLOCK_READ_COST = 1.0;
        PolicyConstants.MEMORY_BLOCK_READ_COST = 0.25;
        PolicyConstants.ROW_EVALUATE_COST = 0.01;
        PolicyConstants.UDF_INVOCATION_COST = 0.00054;
        PolicyConstants.POLICY_EVAL_COST = 0.0000044;
        PolicyConstants.NUMBER_OF_PREDICATES_EVALUATED = 0.66;

        List<String> attrList = new ArrayList<>(attrs);
        PolicyConstants.ATTRIBUTES = attrList;
        PolicyConstants.INDEXED_ATTRIBUTES = new ArrayList<>(attrList);
        PolicyConstants.RANGED_ATTRIBUTES = new ArrayList<>(rangeAttrs);

        Map<String, String> indexMap = new LinkedHashMap<>();
        for (String a : attrList) {
            indexMap.put(a, a + "_idx");
        }
        PolicyConstants.ATTRIBUTE_INDEXES = indexMap;

        setStaticField(PolicyConstants.class, "connection", conn);
        setStaticField(PolicyConstants.class, "NUMBER_OF_TUPLES", countTableRows(conn, targetTable));
    }

    private static String stripTrailingSemicolon(String sql) {
        String s = sql == null ? "" : sql.trim();
        if (s.endsWith(";")) {
            s = s.substring(0, s.length() - 1).trim();
        }
        return s;
    }

    private static String replaceTableToken(String sql, String targetTable, String replacement) {
        String s = sql;
        StringBuilder out = new StringBuilder();
        boolean inSingle = false;
        boolean inDouble = false;

        int i = 0;
        while (i < s.length()) {
            char ch = s.charAt(i);
            if (ch == '\'' && !inDouble) {
                inSingle = !inSingle;
                out.append(ch);
                i += 1;
                continue;
            }
            if (ch == '"' && !inSingle) {
                inDouble = !inDouble;
                out.append(ch);
                i += 1;
                continue;
            }
            if (!inSingle
                    && !inDouble
                    && i + targetTable.length() <= s.length()
                    && s.regionMatches(true, i, targetTable, 0, targetTable.length())) {
                char prev = (i > 0) ? s.charAt(i - 1) : ' ';
                int end = i + targetTable.length();
                char next = (end < s.length()) ? s.charAt(end) : ' ';
                if (isWordBoundary(prev) && isWordBoundary(next)) {
                    out.append(replacement);
                    i += targetTable.length();
                    continue;
                }
            }
            out.append(ch);
            i += 1;
        }
        return out.toString();
    }

    private static String rewriteWithSieve(String originalSql, String targetTable, List<BEPolicy> allowPolicies) {
        String query = stripTrailingSemicolon(originalSql);
        if (query.isEmpty()) {
            return "";
        }
        String replaced = replaceTableToken(query, targetTable, "polEval");
        if (replaced.equals(query)) {
            return query;
        }
        if (allowPolicies.isEmpty()) {
            return "SELECT * FROM (" + query + ") AS sieve_empty WHERE false";
        }

        BEExpression allowExp = new BEExpression(allowPolicies);
        SelectGuard sg = new SelectGuard(allowExp, false);
        if (sg.numberOfGuards() <= 0) {
            return query;
        }
        GuardExp guardExp = sg.create(DEMO_QUERIER, "user");
        String guardUnion = guardExp.createQueryWithUnion(true);
        return "WITH polEval as (" + guardUnion + ") " + replaced;
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
                List<PolicyEntry> entries = readPolicyEntries(policyPath);
                String targetTable = extractSingleTargetTable(entries);
                List<List<String>> allowTerms = composeAllowTermsOddEven(entries);
                ingestPoliciesWithOddEvenDemoContext(conn, allowTerms);
                List<BEPolicy> allowPolicies = buildAllowPoliciesFromTerms(allowTerms);
                if (!targetTable.isEmpty()) {
                    initializePolicyConstantsForSieve(conn, targetTable, allowPolicies);
                }
                rewritten = rewriteWithSieve(query, targetTable, allowPolicies);
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
