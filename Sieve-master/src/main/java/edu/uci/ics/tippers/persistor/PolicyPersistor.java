package edu.uci.ics.tippers.persistor;

import edu.uci.ics.tippers.common.AttributeType;
import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.model.policy.*;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class PolicyPersistor {

    private static final PolicyPersistor _instance = new PolicyPersistor();
    //TODO: Generalize this database connection
    private static Connection connection;

    private PolicyPersistor(){

    }

    public static PolicyPersistor getInstance() {
        connection = PolicyConstants.getDBMSConnection();
        return _instance;
    }

    /**
     * Inserts a list of policies into a relational table based on whether it's a user policy or a group policy
     *
     * @param bePolicies
     */
    public void insertPolicy(List<BEPolicy> bePolicies) {
        String userPolicyInsert = "INSERT INTO USER_POLICY " +  //
                "(id, querier, purpose, enforcement_action, inserted_at) VALUES (?, ?, ?, ?, ?)";
        String userobjectConditionInsert = "INSERT INTO USER_POLICY_OBJECT_CONDITION " +
                "(policy_id, attribute, attribute_type, operator, comp_value) VALUES (?, ?, ?, ?, ?)";
        String groupPolicyInsert = "INSERT INTO GROUP_POLICY " +
                "(id, querier, purpose, enforcement_action, inserted_at) VALUES (?, ?, ?, ?, ?)";
        String groupObjectConditionInsert = "INSERT INTO GROUP_POLICY_OBJECT_CONDITION " +
                "(policy_id, attribute, attribute_type, operator, comp_value) VALUES (?, ?, ?, ?, ?)";

        boolean USER_POLICY = true;

        try {
            PreparedStatement userPolicyStmt = connection.prepareStatement(userPolicyInsert);
            PreparedStatement userOcStmt = connection.prepareStatement(userobjectConditionInsert);

            PreparedStatement groupPolicyStmt = connection.prepareStatement(groupPolicyInsert);
            PreparedStatement groupOcStmt = connection.prepareStatement(groupObjectConditionInsert);
            int policyCount = 0;

            for (BEPolicy bePolicy : bePolicies) {
                if (bePolicy.typeOfPolicy()) { //User Policy
                    userPolicyStmt.setString(1, bePolicy.getId());
                    userPolicyStmt.setInt(2, Integer.parseInt(bePolicy.fetchQuerier()));
                    userPolicyStmt.setString(3, bePolicy.getPurpose());
                    userPolicyStmt.setString(4, bePolicy.getAction());
                    userPolicyStmt.setTimestamp(5, bePolicy.getInserted_at());
                    userPolicyStmt.addBatch();

                    for (ObjectCondition oc : bePolicy.getObject_conditions()) {
                        for (BooleanPredicate bp : oc.getBooleanPredicates()) {
                            userOcStmt.setString(1, bePolicy.getId());
                            userOcStmt.setString(2, oc.getAttribute());
                            userOcStmt.setString(3, oc.getType().toString());
                            userOcStmt.setString(4, bp.getOperator().toString());
                            userOcStmt.setString(5, bp.getValue());
                            userOcStmt.addBatch();
                        }
                    }
                    policyCount++;

                } else { //Group Policy
                    USER_POLICY = false;

                    groupPolicyStmt.setString(1, bePolicy.getId());
                    groupPolicyStmt.setInt(2, Integer.parseInt(bePolicy.fetchQuerier()));
                    groupPolicyStmt.setString(3, bePolicy.getPurpose());
                    groupPolicyStmt.setString(4, bePolicy.getAction());
                    groupPolicyStmt.setTimestamp(5, bePolicy.getInserted_at());
                    groupPolicyStmt.addBatch();
                    groupPolicyStmt.close();

                    for (ObjectCondition oc : bePolicy.getObject_conditions()) {
                        for (BooleanPredicate bp : oc.getBooleanPredicates()) {
                            groupOcStmt.setString(1, bePolicy.getId());
                            groupOcStmt.setString(2, oc.getAttribute());
                            groupOcStmt.setString(3, oc.getType().toString());
                            groupOcStmt.setString(4, bp.getOperator().toString());
                            groupOcStmt.setString(5, bp.getValue());
                            groupOcStmt.addBatch();
                        }
                    }
                }
                if (USER_POLICY) {
//                    if (policyCount % 100 == 0) {
                        userPolicyStmt.executeBatch();
                        userOcStmt.executeBatch();
//                        System.out.println("# " + policyCount + " inserted");
//                    }
                } else {
                    groupPolicyStmt.executeBatch();
                    groupOcStmt.executeBatch();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void insertPolicy(List<BEPolicy> bePolicies, String tablename) {
        String userPolicyInsert = "INSERT INTO " + tablename + " " +  //
                "(id, querier, purpose, enforcement_action, inserted_at) VALUES (?, ?, ?, ?, ?)";
        String userobjectConditionInsert = "INSERT INTO " + tablename + "_OBJECT_CONDITION " +
                "(policy_id, attribute, attribute_type, operator, comp_value) VALUES (?, ?, ?, ?, ?)";
        String groupPolicyInsert = "INSERT INTO " + tablename + "_GROUP_POLICY " +
                "(id, querier, purpose, enforcement_action, inserted_at) VALUES (?, ?, ?, ?, ?)";
        String groupObjectConditionInsert = "INSERT INTO " + tablename + "_GROUP_POLICY_OBJECT_CONDITION " +
                "(policy_id, attribute, attribute_type, operator, comp_value) VALUES (?, ?, ?, ?, ?)";

        boolean USER_POLICY = true;

        try {
            PreparedStatement userPolicyStmt = connection.prepareStatement(userPolicyInsert);
            PreparedStatement userOcStmt = connection.prepareStatement(userobjectConditionInsert);

            PreparedStatement groupPolicyStmt = connection.prepareStatement(groupPolicyInsert);
            PreparedStatement groupOcStmt = connection.prepareStatement(groupObjectConditionInsert);

            for (BEPolicy bePolicy : bePolicies) {
                if (bePolicy.typeOfPolicy()) { //User Policy
                    userPolicyStmt.setString(1, bePolicy.getId());
                    userPolicyStmt.setInt(2, Integer.parseInt(bePolicy.fetchQuerier()));
                    userPolicyStmt.setString(3, bePolicy.getPurpose());
                    userPolicyStmt.setString(4, bePolicy.getAction());
                    userPolicyStmt.setTimestamp(5, bePolicy.getInserted_at());
                    userPolicyStmt.addBatch();

                    for (ObjectCondition oc : bePolicy.getObject_conditions()) {
                        for (BooleanPredicate bp : oc.getBooleanPredicates()) {
                            userOcStmt.setString(1, bePolicy.getId());
                            userOcStmt.setString(2, oc.getAttribute());
                            userOcStmt.setString(3, oc.getType().toString());
                            userOcStmt.setString(4, bp.getOperator().toString());
                            userOcStmt.setString(5, bp.getValue());
                            userOcStmt.addBatch();
                        }
                    }
                } else { //Group Policy
                    USER_POLICY = false;

                    groupPolicyStmt.setString(1, bePolicy.getId());
                    groupPolicyStmt.setInt(2, Integer.parseInt(bePolicy.fetchQuerier()));
                    groupPolicyStmt.setString(3, bePolicy.getPurpose());
                    groupPolicyStmt.setString(4, bePolicy.getAction());
                    groupPolicyStmt.setTimestamp(5, bePolicy.getInserted_at());
                    groupPolicyStmt.addBatch();
                    groupPolicyStmt.close();

                    for (ObjectCondition oc : bePolicy.getObject_conditions()) {
                        for (BooleanPredicate bp : oc.getBooleanPredicates()) {
                            groupOcStmt.setString(1, bePolicy.getId());
                            groupOcStmt.setString(2, oc.getAttribute());
                            groupOcStmt.setString(3, oc.getType().toString());
                            groupOcStmt.setString(4, bp.getOperator().toString());
                            groupOcStmt.setString(5, bp.getValue());
                            groupOcStmt.addBatch();
                        }
                    }
                }
                if (USER_POLICY) {
                    userPolicyStmt.executeBatch();
                    userOcStmt.executeBatch();
                } else {
                    groupPolicyStmt.executeBatch();
                    groupOcStmt.executeBatch();
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private Operation convertOperator(String operator) {
        if (operator.equalsIgnoreCase("=")) return Operation.EQ;
        else if (operator.equalsIgnoreCase(">=")) return Operation.GTE;
        else if (operator.equalsIgnoreCase("<=")) return Operation.LTE;
        else if (operator.equalsIgnoreCase("<")) return Operation.LT;
        else return Operation.GT;
    }

    public List<BEPolicy> retrievePolicies(String querier, String querier_type, String enforcement_action) {
        List<BEPolicy> bePolicies = new ArrayList<>();
        String id = null, purpose = null, action = null;
        Timestamp inserted_at = null;

        String policy_table = null, oc_table = null;
        if (querier_type.equalsIgnoreCase("user")) {
            policy_table = "USER_POLICY";
            oc_table = "USER_POLICY_OBJECT_CONDITION";
        } else if (querier_type.equalsIgnoreCase("group")) {
            policy_table = "GROUP_POLICY";
            oc_table = "GROUP_POLICY_OBJECT_CONDITION";
        }
        PreparedStatement queryStm = null;
        try {
            if (querier != null) {
                queryStm = connection.prepareStatement("SELECT " + policy_table + ".id as \"" + policy_table + ".id\"," +
                        policy_table + ".querier as \"" + policy_table + ".querier\"," +
                        policy_table + ".purpose as \"" + policy_table + ".purpose\", " +
                        policy_table + ".enforcement_action as \"" + policy_table + ".enforcement_action\"," +
                        policy_table + ".inserted_at as \"" + policy_table + ".inserted_at\"," +
                        oc_table + ".id as \"" + oc_table + ".id\", " +
                        oc_table + ".policy_id as \"" + oc_table + ".policy_id\"," +
                        oc_table + ".attribute as \"" + oc_table + ".attribute\", " +
                        oc_table + ".attribute_type as \"" + oc_table + ".attribute_type\", " +
                        oc_table + ".operator as \"" + oc_table + ".operator\"," +
                        oc_table + ".comp_value as \"" + oc_table + ".comp_value\" " +
                        "FROM " + policy_table + ", " + oc_table +
                        " WHERE " + policy_table + ".querier=? AND " + policy_table + ".id = " + oc_table + ".policy_id " +
                        "AND " + policy_table + ".enforcement_action=? " +
                        " order by " + policy_table + ".id, " + oc_table + ".attribute, " + oc_table + ".comp_value");
                queryStm.setString(1, querier);
                queryStm.setString(2, enforcement_action);
            } else {
                queryStm = connection.prepareStatement("SELECT " + policy_table + ".id, " + policy_table + ".querier, " + policy_table + ".purpose, " +
                        policy_table + ".enforcement_action," + policy_table + ".inserted_at," + oc_table + ".id, " + oc_table + " .policy_id," + oc_table + ".attribute, " +
                        oc_table + ".attribute_type, " + oc_table + ".operator," + oc_table + ".comp_value " +
                        "FROM " + policy_table + ", " + oc_table +
                        " WHERE " + policy_table + ".id = " + oc_table + ".policy_id " +
                        "AND " + policy_table + ".enforcement_action=? " +
                        "order by " + policy_table + ".id, " + oc_table + ".attribute, " + oc_table + ".comp_value");
                queryStm.setString(1, enforcement_action);
            }
            ResultSet rs = queryStm.executeQuery();
            if (!rs.next()) return null;
            String next = null;
            boolean skip = false;
            List<QuerierCondition> querierConditions = new ArrayList<>();
            List<ObjectCondition> objectConditions = new ArrayList<>();
            while (true) {
                if (!skip) {
                    id = rs.getString(policy_table + ".id");
                    purpose = rs.getString(policy_table + ".purpose");
                    action = rs.getString(policy_table + ".enforcement_action");
                    inserted_at = rs.getTimestamp(policy_table + ".inserted_at");
                    querier = rs.getString(policy_table + ".querier");

                    querierConditions = new ArrayList<>();
                    QuerierCondition qc1 = new QuerierCondition();
                    qc1.setPolicy_id(id);
                    qc1.setAttribute("policy_type");
                    qc1.setType(AttributeType.STRING);
                    List<BooleanPredicate> qbps1 = new ArrayList<>();
                    BooleanPredicate qbp1 = new BooleanPredicate();
                    qbp1.setOperator(Operation.EQ);
                    qbp1.setValue(querier_type);
                    qbps1.add(qbp1);
                    qc1.setBooleanPredicates(qbps1);
                    querierConditions.add(qc1);
                    QuerierCondition qc2 = new QuerierCondition();
                    qc2.setPolicy_id(id);
                    qc2.setAttribute("querier");
                    qc2.setType(AttributeType.STRING);
                    List<BooleanPredicate> qbps2 = new ArrayList<>();
                    BooleanPredicate qbp2 = new BooleanPredicate();
                    qbp2.setOperator(Operation.EQ);
                    qbp2.setValue(querier);
                    qbps2.add(qbp2);
                    qc2.setBooleanPredicates(qbps2);
                    querierConditions.add(qc2);
                    objectConditions = new ArrayList<>();
                }
                ObjectCondition oc = new ObjectCondition();
                oc.setAttribute(rs.getString(oc_table + ".attribute"));
                oc.setPolicy_id(rs.getString(oc_table + ".policy_id"));
                oc.setType(AttributeType.valueOf(rs.getString(oc_table + ".attribute_type")));
                List<BooleanPredicate> booleanPredicates = new ArrayList<>();
                BooleanPredicate bp1 = new BooleanPredicate();
                bp1.setOperator(convertOperator(rs.getString(oc_table + ".operator")));
                bp1.setValue(rs.getString(oc_table + ".comp_value"));
                rs.next();
                BooleanPredicate bp2 = new BooleanPredicate();
                bp2.setOperator(convertOperator(rs.getString(oc_table + ".operator")));
                bp2.setValue(rs.getString(oc_table + ".comp_value"));
                booleanPredicates.add(bp1);
                booleanPredicates.add(bp2);
                oc.setBooleanPredicates(booleanPredicates);
                objectConditions.add(oc);

                if (!rs.next()) {
                    BEPolicy bePolicy = new BEPolicy(id, objectConditions, querierConditions, purpose, action, inserted_at);
                    bePolicies.add(bePolicy);
                    break;
                }

                next = rs.getString(policy_table + ".id");
                if (!id.equalsIgnoreCase(next)) {
                    BEPolicy bePolicy = new BEPolicy(id, objectConditions, querierConditions, purpose, action, inserted_at);
                    bePolicies.add(bePolicy);
                    skip = false;
                } else skip = true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return bePolicies;
    }

    public List<BEPolicy> retrievePolicies(
            String querier,
            String querier_type,
            String enforcement_action,
            List<String> locations,      // e.g., ["3144-clwa-4051","3142-clwa-2051"]; null/empty = no filter
            String timeStart, String timeEnd,   // e.g., "08:00:00" .. "17:00:00"; both non-null to enable
            String dateStart, String dateEnd    // e.g., "2018-02-01" .. "2018-03-10"; both non-null to enable
    ) {
        List<BEPolicy> bePolicies = new ArrayList<>();
        String id = null, purpose = null, action = null;
        Timestamp inserted_at = null;

        String policy_table = null, oc_table = null;
        if (querier_type.equalsIgnoreCase("user")) {
            policy_table = "USER_POLICY";
            oc_table = "USER_POLICY_OBJECT_CONDITION";
        } else if (querier_type.equalsIgnoreCase("group")) {
            policy_table = "GROUP_POLICY";
            oc_table = "GROUP_POLICY_OBJECT_CONDITION";
        }

        PreparedStatement queryStm = null;
        try {
            // ---------- Build SELECT + WHERE dynamically (keeps your aliases) ----------
            StringBuilder sql = new StringBuilder();
            sql.append("SELECT ")
                    .append(policy_table).append(".id as \"").append(policy_table).append(".id\",")
                    .append(policy_table).append(".querier as \"").append(policy_table).append(".querier\",")
                    .append(policy_table).append(".purpose as \"").append(policy_table).append(".purpose\", ")
                    .append(policy_table).append(".enforcement_action as \"").append(policy_table).append(".enforcement_action\",")
                    .append(policy_table).append(".inserted_at as \"").append(policy_table).append(".inserted_at\",")
                    .append(oc_table).append(".id as \"").append(oc_table).append(".id\", ")
                    .append(oc_table).append(".policy_id as \"").append(oc_table).append(".policy_id\",")
                    .append(oc_table).append(".attribute as \"").append(oc_table).append(".attribute\", ")
                    .append(oc_table).append(".attribute_type as \"").append(oc_table).append(".attribute_type\", ")
                    .append(oc_table).append(".operator as \"").append(oc_table).append(".operator\",")
                    .append(oc_table).append(".comp_value as \"").append(oc_table).append(".comp_value\" ")
                    .append("FROM ").append(policy_table).append(", ").append(oc_table).append(" ")
                    .append("WHERE ").append(policy_table).append(".id = ").append(oc_table).append(".policy_id ");

            List<Object> params = new ArrayList<>();

            // (a) Querier filter (same as your current behavior when provided)
            if (querier != null) {
                sql.append("AND ").append(policy_table).append(".querier = ? ");
                params.add(querier);
            }

            // (b) Enforcement action (same as today)
            if (enforcement_action != null) {
                sql.append("AND ").append(policy_table).append(".enforcement_action = ? ");
                params.add(enforcement_action);
            }

            // ---------- OPTIONAL FILTERS ----------
            // 1) Location IN (...)
            if (locations != null && !locations.isEmpty()) {
                sql.append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" loc ")
                        .append("  WHERE loc.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND loc.attribute = ? ")
                        .append("    AND loc.operator = '=' ")
                        .append("    AND loc.comp_value IN (");
                params.add("location_id"); // change if your attribute key differs

                for (int i = 0; i < locations.size(); i++) {
                    if (i > 0) sql.append(",");
                    sql.append("?");
                    params.add(locations.get(i));
                }
                sql.append(")) ");
            }

            // 2) TIME overlap: policy [pStart, pEnd] overlaps query [timeStart, timeEnd]
            // Stored as two rows in OC for attribute 'start_time': (>= lower) and (<= upper)
            if (timeStart != null && timeEnd != null) {
                sql.append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" t1 ")
                        .append("  WHERE t1.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND t1.attribute = ? ")
                        .append("    AND t1.operator = '>=') ")
                        .append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" t2 ")
                        .append("  WHERE t2.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND t2.attribute = ? ")
                        .append("    AND t2.operator = '<=') ")
                        // overlap: (pStart <= queryEnd) AND (pEnd >= queryStart)
                        .append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" tl ")
                        .append("  WHERE tl.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND tl.attribute = ? ")
                        .append("    AND tl.operator = '>=' ")
                        .append("    AND tl.comp_value <= ?) ")
                        .append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" tu ")
                        .append("  WHERE tu.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND tu.attribute = ? ")
                        .append("    AND tu.operator = '<=' ")
                        .append("    AND tu.comp_value >= ?) ");
                params.add("start_time");
                params.add("start_time");
                params.add("start_time");
                params.add(timeEnd);   // "HH:mm:ss"
                params.add("start_time");
                params.add(timeStart); // "HH:mm:ss"
            }

            // 3) DATE overlap: policy [pStart, pEnd] overlaps query [dateStart, dateEnd]
            // Stored as two rows in OC for attribute 'start_date': (>= lower) and (<= upper)
            if (dateStart != null && dateEnd != null) {
                sql.append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" d1 ")
                        .append("  WHERE d1.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND d1.attribute = ? ")
                        .append("    AND d1.operator = '>=') ")
                        .append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" d2 ")
                        .append("  WHERE d2.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND d2.attribute = ? ")
                        .append("    AND d2.operator = '<=') ")
                        // overlap: (pStart <= queryEnd) AND (pEnd >= queryStart)
                        .append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" dl ")
                        .append("  WHERE dl.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND dl.attribute = ? ")
                        .append("    AND dl.operator = '>=' ")
                        .append("    AND dl.comp_value <= ?) ")
                        .append("AND EXISTS (")
                        .append("  SELECT 1 FROM ").append(oc_table).append(" du ")
                        .append("  WHERE du.policy_id = ").append(policy_table).append(".id ")
                        .append("    AND du.attribute = ? ")
                        .append("    AND du.operator = '<=' ")
                        .append("    AND du.comp_value >= ?) ");
                params.add("start_date");
                params.add("start_date");
                params.add("start_date");
                params.add(dateEnd);   // "YYYY-MM-DD"
                params.add("start_date");
                params.add(dateStart); // "YYYY-MM-DD"
            }

            sql.append(" ORDER BY ").append(policy_table).append(".id, ")
                    .append(oc_table).append(".attribute, ")
                    .append(oc_table).append(".comp_value");

            queryStm = connection.prepareStatement(sql.toString());

            // Bind params in order
            int idx = 1;
            for (Object o : params) {
                queryStm.setString(idx++, String.valueOf(o));
            }

            ResultSet rs = queryStm.executeQuery();
            if (!rs.next()) return null;

            String next = null;
            boolean skip = false;
            List<QuerierCondition> querierConditions = new ArrayList<>();
            List<ObjectCondition> objectConditions = new ArrayList<>();

            // ---------- Your original assembly logic (unchanged) ----------
            while (true) {
                if (!skip) {
                    id = rs.getString(policy_table + ".id");
                    purpose = rs.getString(policy_table + ".purpose");
                    action = rs.getString(policy_table + ".enforcement_action");
                    inserted_at = rs.getTimestamp(policy_table + ".inserted_at");
                    querier = rs.getString(policy_table + ".querier");

                    querierConditions = new ArrayList<>();
                    QuerierCondition qc1 = new QuerierCondition();
                    qc1.setPolicy_id(id);
                    qc1.setAttribute("policy_type");
                    qc1.setType(AttributeType.STRING);
                    List<BooleanPredicate> qbps1 = new ArrayList<>();
                    BooleanPredicate qbp1 = new BooleanPredicate();
                    qbp1.setOperator(Operation.EQ);
                    qbp1.setValue(querier_type);
                    qbps1.add(qbp1);
                    qc1.setBooleanPredicates(qbps1);
                    querierConditions.add(qc1);

                    QuerierCondition qc2 = new QuerierCondition();
                    qc2.setPolicy_id(id);
                    qc2.setAttribute("querier");
                    qc2.setType(AttributeType.STRING);
                    List<BooleanPredicate> qbps2 = new ArrayList<>();
                    BooleanPredicate qbp2 = new BooleanPredicate();
                    qbp2.setOperator(Operation.EQ);
                    qbp2.setValue(querier);
                    qbps2.add(qbp2);
                    qc2.setBooleanPredicates(qbps2);
                    querierConditions.add(qc2);

                    objectConditions = new ArrayList<>();
                }

                ObjectCondition oc = new ObjectCondition();
                oc.setAttribute(rs.getString(oc_table + ".attribute"));
                oc.setPolicy_id(rs.getString(oc_table + ".policy_id"));
                oc.setType(AttributeType.valueOf(rs.getString(oc_table + ".attribute_type")));
                List<BooleanPredicate> booleanPredicates = new ArrayList<>();
                BooleanPredicate bp1 = new BooleanPredicate();
                bp1.setOperator(convertOperator(rs.getString(oc_table + ".operator")));
                bp1.setValue(rs.getString(oc_table + ".comp_value"));
                rs.next();
                BooleanPredicate bp2 = new BooleanPredicate();
                bp2.setOperator(convertOperator(rs.getString(oc_table + ".operator")));
                bp2.setValue(rs.getString(oc_table + ".comp_value"));
                booleanPredicates.add(bp1);
                booleanPredicates.add(bp2);
                oc.setBooleanPredicates(booleanPredicates);
                objectConditions.add(oc);

                if (!rs.next()) {
                    BEPolicy bePolicy = new BEPolicy(id, objectConditions, querierConditions, purpose, action, inserted_at);
                    bePolicies.add(bePolicy);
                    break;
                }

                next = rs.getString(policy_table + ".id");
                if (!id.equalsIgnoreCase(next)) {
                    BEPolicy bePolicy = new BEPolicy(id, objectConditions, querierConditions, purpose, action, inserted_at);
                    bePolicies.add(bePolicy);
                    skip = false;
                } else skip = true;
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }

        return bePolicies;
    }

    public BEPolicy retrievePolicy(String policy_id, String querier_type) {
        String id = null, purpose = null, action = null, querier = null;
        Timestamp inserted_at = null;
        List<QuerierCondition> querierConditions = new ArrayList<>();
        List<ObjectCondition> objectConditions = new ArrayList<>();

        String policy_table = null, oc_table = null;
        if (querier_type.equalsIgnoreCase("user")) {
            policy_table = "USER_POLICY";
            oc_table = "USER_POLICY_OBJECT_CONDITION";
        } else if (querier_type.equalsIgnoreCase("group")) {
            policy_table = "GROUP_POLICY";
            oc_table = "GROUP_POLICY_OBJECT_CONDITION";
        }
        PreparedStatement queryStm = null;
        try {
            queryStm = connection.prepareStatement("SELECT " + policy_table + ".id, " + policy_table + ".querier, " + policy_table + ".purpose, " +
                    policy_table + ".enforcement_action," + policy_table + ".inserted_at," + oc_table + ".id, " + oc_table + " .policy_id," + oc_table + ".attribute, " +
                    oc_table + ".attribute_type, " + oc_table + ".operator," + oc_table + ".comp_value " +
                    "FROM " + policy_table + ", " + oc_table +
                    " WHERE " + policy_table + ".id = " + oc_table + ".policy_id " +
                    "AND " + policy_table + ".id=? ");
            queryStm.setString(1, policy_id);
            ResultSet rs = queryStm.executeQuery();
            boolean skip = false;
            while (rs.next()) {
                if (!skip) {
                    id = rs.getString(policy_table + ".id");
                    purpose = rs.getString(policy_table + ".purpose");
                    action = rs.getString(policy_table + ".enforcement_action");
                    inserted_at = rs.getTimestamp(policy_table + ".inserted_at");
                    querier = rs.getString(policy_table + ".querier");

                    querierConditions = new ArrayList<>();
                    QuerierCondition qc1 = new QuerierCondition();
                    qc1.setPolicy_id(id);
                    qc1.setAttribute("policy_type");
                    qc1.setType(AttributeType.STRING);
                    List<BooleanPredicate> qbps1 = new ArrayList<>();
                    BooleanPredicate qbp1 = new BooleanPredicate();
                    qbp1.setOperator(Operation.EQ);
                    qbp1.setValue(querier_type);
                    qbps1.add(qbp1);
                    qc1.setBooleanPredicates(qbps1);
                    querierConditions.add(qc1);
                    QuerierCondition qc2 = new QuerierCondition();
                    qc2.setPolicy_id(id);
                    qc2.setAttribute("querier");
                    qc2.setType(AttributeType.STRING);
                    List<BooleanPredicate> qbps2 = new ArrayList<>();
                    BooleanPredicate qbp2 = new BooleanPredicate();
                    qbp2.setOperator(Operation.EQ);
                    qbp2.setValue(querier);
                    qbps2.add(qbp2);
                    qc2.setBooleanPredicates(qbps2);
                    querierConditions.add(qc2);
                    objectConditions = new ArrayList<>();
                    skip = true;
                }
                ObjectCondition oc = new ObjectCondition();
                oc.setAttribute(rs.getString(oc_table + ".attribute"));
                oc.setPolicy_id(rs.getString(oc_table + ".policy_id"));
                oc.setType(AttributeType.valueOf(rs.getString(oc_table + ".attribute_type")));
                List<BooleanPredicate> booleanPredicates = new ArrayList<>();
                BooleanPredicate bp1 = new BooleanPredicate();
                bp1.setOperator(convertOperator(rs.getString(oc_table + ".operator")));
                bp1.setValue(rs.getString(oc_table + ".comp_value"));
                rs.next();
                BooleanPredicate bp2 = new BooleanPredicate();
                bp2.setOperator(convertOperator(rs.getString(oc_table + ".operator")));
                bp2.setValue(rs.getString(oc_table + ".comp_value"));
                booleanPredicates.add(bp1);
                booleanPredicates.add(bp2);
                oc.setBooleanPredicates(booleanPredicates);
                objectConditions.add(oc);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new BEPolicy(id, objectConditions, querierConditions, purpose, action, inserted_at);
    }
}
