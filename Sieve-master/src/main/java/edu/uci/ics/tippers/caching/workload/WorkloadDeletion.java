package edu.uci.ics.tippers.caching.workload;

import edu.uci.ics.tippers.caching.CachingAlgorithm;
import edu.uci.ics.tippers.caching.CircularHashMap;
import edu.uci.ics.tippers.caching.ClockHashMap;
import edu.uci.ics.tippers.caching.costmodel.Baseline1;

import edu.uci.ics.tippers.caching.costmodel.CostModelsExp;

import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.dbms.mysql.MySQLConnectionManager;
import edu.uci.ics.tippers.execution.experiments.performance.QueryPerformance;
import edu.uci.ics.tippers.fileop.Writer;

import edu.uci.ics.tippers.model.guard.GuardExp;
import edu.uci.ics.tippers.model.policy.BEPolicy;
import edu.uci.ics.tippers.model.query.QueryStatement;
import edu.uci.ics.tippers.persistor.PolicyPersistor;

import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class WorkloadDeletion {
    private int regularInterval;
    private int dynamicIntervalStart;
    private int duration;
    PolicyPersistor polper;
    QueryPerformance e;
    CachingAlgorithm ca;
    CostModelsExp cme;
    Baseline1 baseline1;
    ClockHashMap<String, GuardExp> clockMap;

    private Connection connection;

    public WorkloadDeletion(int regularInterval, int dynamicIntervalStart, int duration) {
        this.regularInterval = regularInterval;
        this.dynamicIntervalStart = dynamicIntervalStart;
        this.duration = duration;
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        ca = new CachingAlgorithm();
        cme = new CostModelsExp();
        baseline1 = new Baseline1<>();
        clockMap = new ClockHashMap<>();
        connection = MySQLConnectionManager.getInstance().getConnection();
    }

    public WorkloadDeletion(int regularInterval) {
        this.regularInterval = regularInterval;
        this.dynamicIntervalStart = 0;
        this.duration = 0;
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        ca = new CachingAlgorithm();
        cme = new CostModelsExp();
        baseline1 = new Baseline1<>();
        clockMap = new ClockHashMap<>(3);
        connection = MySQLConnectionManager.getInstance().getConnection();
    }

    public Duration generateWorkload(int n, List<BEPolicy> policies, List<QueryStatement> queries) {
        int currentTime = 0;
        int nextRegularPolicyInsertionTime = 0;
        int sizeOfPolicies = policies.size();
        int windowSize = 10;
        int generatedQueries = 0;
        int yQuery = 5;
        int dPolicy = 5;
        boolean cachingFlag = false;
        LinkedList<QueryStatement> queryWindow = new LinkedList<>();

//      Bursty State variables
        int insertedPolicies = 0;
        int initialPolicyRate = 30;
        int finalPolicyRate = 1;
        int initialQueryRate = 1;
        int finalQueryRate = 10;
        int totalCycles = 31520;
        boolean bursty = false;


        QueryStatement query = new QueryStatement();
        Random random = new Random();
        int batchSize = 2;
        List<QueryStatement> batchQueries = new ArrayList<>();

        CircularHashMap<String,Timestamp> timestampDirectory = new CircularHashMap<>(320);
        ClockHashMap<String, GuardExp> clockHashMap = new ClockHashMap<>(320);
        CircularHashMap<String, Integer> countUpdate = new CircularHashMap<>(400);
        HashMap<String,Integer> deletionHashMap = new HashMap<>();

        Writer writer = new Writer();
        StringBuilder result = new StringBuilder();

        String fileName = "deletion10P5Q5D_NC.txt";

        boolean first = true;

        result.append("No. of policies= "). append(policies.size()).append("\n")
                .append("No. of queries= ").append(queries.size()).append("\n");
        writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);

        Instant fsStart = Instant.now();

        if(cachingFlag){
            System.out.println("!!!Deletion+Caching!!!");

                while (!queries.isEmpty() && !policies.isEmpty()) {
                    if (currentTime == 0 || currentTime == nextRegularPolicyInsertionTime) {
                        List<BEPolicy> regularPolicies = extractPolicies(policies, n);

                        //Insert policy into database
                        for (BEPolicy policy : regularPolicies) {
                            result.append(currentTime).append(",")
                                    .append(policy.toString()).append("\n");
                            Instant pinsert = Instant.now();
                            Timestamp policyinsertionTime = Timestamp.from(pinsert);
                            timestampDirectory.put(policy.fetchQuerier(), policyinsertionTime);
                            policy.setInserted_at(policyinsertionTime);
                        }
                        nextRegularPolicyInsertionTime += regularInterval;

                        polper.insertPolicy(regularPolicies);
                    }


//                Steady State
                    for (int i = 0; i < yQuery; i++) {
                        if (generatedQueries < 15760) {
                            if (generatedQueries % 2 == 0) {
                                if (queryWindow.size() < windowSize) {
                                    queryWindow.add(queries.remove(0));
                                } else {
                                    queryWindow.removeFirst();
                                    queryWindow.add(queries.remove(0));
                                }
                                query = queryWindow.getLast();
                            } else {
                                int index = random.nextInt(queryWindow.size());
                                query = queryWindow.get(index);
                            }
                            generatedQueries++;
                            result.append(currentTime).append(",")
                                    .append(query.toString()).append("\n");
                            String querier = e.runExperiment(query);
                            ca.runAlgorithm(clockHashMap, querier, query, timestampDirectory, deletionHashMap);
                            deletionHashMap.put(querier,0);
//                        cme.runAlgorithm(clockHashMap, querier, query, timestampDirectory);
//                baseline1.runAlgorithm(clockHashMap, querier, query, timestampDirectory, countUpdate);
                        }
                    }

                    List<String> keys = new ArrayList<>(deletionHashMap.keySet());
                    for(int i=0; i<dPolicy; i++){
                        Random rand = new Random();
                        String randQuerier = keys.get(rand.nextInt(keys.size()));
                        List<BEPolicy> allowPolicies = polper.retrievePolicies(randQuerier,
                                PolicyConstants.USER_INDIVIDUAL, PolicyConstants.ACTION_ALLOW);

                        BEPolicy deletePolicy = getOldestPolicy(allowPolicies);
                        try{
                            if(deletePolicy != null){
                                Statement statement1 = connection.createStatement();
                                int rowsAffected1 = statement1.executeUpdate("DELETE FROM ashakya.USER_POLICY WHERE id = '" + deletePolicy.getId() + "'");
                                // Check if any rows were deleted
                                if (rowsAffected1 > 0) {
                                    System.out.println("Deletion successful in user_policy table. Rows affected: " + rowsAffected1);
                                } else {
                                    System.out.println("No rows were deleted in user_policy table. The specified ID might not exist.");
                                }
                                Statement statement2 = connection.createStatement();
                                int rowsAffected2 = statement2.executeUpdate("DELETE FROM ashakya.USER_POLICY_OBJECT_CONDITION WHERE policy_id = '" + deletePolicy.getId() + "'");
                                // Check if any rows were deleted
                                if (rowsAffected2 > 0) {
                                    System.out.println("Deletion successful in user_policy_object_condition table. Rows affected: " + rowsAffected2);
                                } else {
                                    System.out.println("No rows were deleted in user_policy_object_condition table. The specified ID might not exist.");
                                }
                                deletionHashMap.put(randQuerier,1);
                            }
                        }catch (SQLException e) {
                            e.printStackTrace();
                        }
                    }

                    // Writing results to file
                    if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                    else first = false;

                    // Clearing StringBuilder for the next iteration
                    result.setLength(0);

                    currentTime++;

                }
        }else{
            System.out.println("!!! Without Caching!!!");
            while (!policies.isEmpty() && !queries.isEmpty()) {
                if (currentTime == 0 || currentTime == nextRegularPolicyInsertionTime) {
                    // Generate regular policies and write them to file
                    List<BEPolicy> regularPolicies = extractPolicies(policies, n);

                    //Insert policy into database
                    for (BEPolicy policy : regularPolicies) {
                        result.append(currentTime).append(",")
                                .append(policy.toString()).append("\n");
                        Instant pinsert = Instant.now();
                        Timestamp policyinsertionTime = Timestamp.from(pinsert);
                        policy.setInserted_at(policyinsertionTime);
                    }
                    nextRegularPolicyInsertionTime += regularInterval;
                    polper.insertPolicy(regularPolicies);
                }



//                Steady State
                for (int i = 0; i < yQuery; i++) {
                    if (generatedQueries <= 15760) {
                        if (generatedQueries % 2 == 0) {
                            if (queryWindow.size() < windowSize) {
                                queryWindow.add(queries.remove(0));
                            } else {
                                queryWindow.removeFirst();
                                queryWindow.add(queries.remove(0));
                            }
                            query = queryWindow.getLast();
                        } else {
                            int index = random.nextInt(queryWindow.size());
                            query = queryWindow.get(index);
                        }
                        generatedQueries++;
                        result.append(currentTime).append(",")
                                .append(query.toString()).append("\n");
                        String querier = e.runExperiment(query);
                        GuardExp GE = ca.SieveGG(querier, query);
                        String answer = e.runGE(querier, query, GE);
                        deletionHashMap.put(querier,0);
                    }
                }

                List<String> keys = new ArrayList<>(deletionHashMap.keySet());
                for(int i=0; i<dPolicy; i++){
                    Random rand = new Random();
                    String randQuerier = keys.get(rand.nextInt(keys.size()));
                    List<BEPolicy> allowPolicies = polper.retrievePolicies(randQuerier,
                            PolicyConstants.USER_INDIVIDUAL, PolicyConstants.ACTION_ALLOW);

                    BEPolicy deletePolicy = getOldestPolicy(allowPolicies);
                    try{
                        if(deletePolicy != null){
                            Statement statement1 = connection.createStatement();
                            int rowsAffected1 = statement1.executeUpdate("DELETE FROM ashakya.USER_POLICY WHERE id = '" + deletePolicy.getId() + "'");
                            // Check if any rows were deleted
                            if (rowsAffected1 > 0) {
                                System.out.println("Deletion successful in user_policy table. Rows affected: " + rowsAffected1);
                            } else {
                                System.out.println("No rows were deleted in user_policy table. The specified ID might not exist.");
                            }
                            Statement statement2 = connection.createStatement();
                            int rowsAffected2 = statement2.executeUpdate("DELETE FROM ashakya.USER_POLICY_OBJECT_CONDITION WHERE policy_id = '" + deletePolicy.getId() + "'");
                            // Check if any rows were deleted
                            if (rowsAffected2 > 0) {
                                System.out.println("Deletion successful in user_policy_object_condition table. Rows affected: " + rowsAffected2);
                            } else {
                                System.out.println("No rows were deleted in user_policy_object_condition table. The specified ID might not exist.");
                            }
                            deletionHashMap.put(randQuerier,1);
                        }
                    }catch (SQLException e) {
                        e.printStackTrace();
                    }
                }


                // Writing results to file
                if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                else first = false;
//        // Add the policies and queries array to the workload JSON object
//        workloadJson.add("Policies_and_Queries", policiesAndQueriesArray);

                // Clearing StringBuilder for the next iteration
                result.setLength(0);

                currentTime++;
            }
        }
        Instant fsEnd = Instant.now();
        Duration totalRunTime = Duration.between(fsStart, fsEnd);
        return totalRunTime;
    }

    private BEPolicy getOldestPolicy (List<BEPolicy> policies){
        if (policies == null || policies.isEmpty())
            return null;
        BEPolicy oldPolicy = policies.get(0);
        for(BEPolicy policy:policies){
            if(policy.getInserted_at().before(oldPolicy.getInserted_at()))
                oldPolicy = policy;
        }
        return oldPolicy;
    }

    private List<BEPolicy> extractPolicies(List<BEPolicy> policies, int n) {
        List<BEPolicy> extractedPolicies = new ArrayList<>();
        for (int i = 0; i < n && !policies.isEmpty(); i++) {
            extractedPolicies.add(policies.remove(0)); // Remove and add the first policy from the list
        }
        return extractedPolicies;
    }

    public void runExperiment() {
        // generating policies

        CUserGen cUserGen = new CUserGen(1);
        List<CUserGen.User> users = cUserGen.retrieveUserDataForAC();

        CPolicyGen cpg = new CPolicyGen();
        List<BEPolicy> policies = cpg.generatePoliciesforAC(users);

        System.out.println("Total number of entries: " + users.size());
        System.out.println("Total number of entries: " + policies.size());
//        for (BEPolicy policy : policies) {
//            System.out.println(policy.toString());
//        }
//        System.out.println();

        int queryCount = 7880;
        boolean[] templates = {true, true, false, false};
        List<QueryStatement> queries = new ArrayList<>();
        for (int i = 0; i < templates.length; i++) {
            if (templates[i]) queries.addAll(e.getQueries(i+1,queryCount));
//            for (QueryStatement query : queries) {
//                System.out.println(query.toString());
//            }
//            System.out.println();
        }

        System.out.println("Total number of entries: " + users.size());
        System.out.println("Total number of policies: " + policies.size());
        System.out.println("Total number of queries: " + queries.size());

        int regularInterval = 1; // Example regular interval
//        int dynamicInterval = 1; // Example dynamic interval
//        int duration = 3;

        WorkloadDeletion generator = new WorkloadDeletion(regularInterval);
//        WorkloadGenerator generator = new WorkloadGenerator(regularInterval, dynamicInterval, duration);

        int numPoliciesQueries = 10; // Example number of policies/queries to generate each interval
        Duration totalRunTime = generator.generateWorkload(numPoliciesQueries, policies, queries);
        System.out.println("Total Run Time: " + totalRunTime);

    }

}

