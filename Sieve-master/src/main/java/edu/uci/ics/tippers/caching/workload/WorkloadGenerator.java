package edu.uci.ics.tippers.caching.workload;

import edu.uci.ics.tippers.caching.CachingAlgorithm;
import edu.uci.ics.tippers.caching.CircularHashMap;
import edu.uci.ics.tippers.caching.ClockHashMap;
import edu.uci.ics.tippers.caching.costmodel.Baseline1;

import edu.uci.ics.tippers.caching.costmodel.CostModelsExp;

import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.execution.experiments.performance.QueryPerformance;
import edu.uci.ics.tippers.fileop.Writer;

import edu.uci.ics.tippers.model.guard.GuardExp;
import edu.uci.ics.tippers.model.guard.SelectGuard;
import edu.uci.ics.tippers.model.policy.BEExpression;
import edu.uci.ics.tippers.model.policy.BEPolicy;
import edu.uci.ics.tippers.model.query.QueryStatement;
import edu.uci.ics.tippers.persistor.PolicyPersistor;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import java.util.DoubleSummaryStatistics;
import java.util.stream.DoubleStream;

public class WorkloadGenerator {
    private int regularInterval;
    private int dynamicIntervalStart;
    private int duration;
    PolicyPersistor polper;
    QueryPerformance e;
    CachingAlgorithm ca;
    CostModelsExp cme;
    Baseline1 baseline1;
    ClockHashMap<String, GuardExp> clockMap;

    public WorkloadGenerator(int regularInterval, int dynamicIntervalStart, int duration) {
        this.regularInterval = regularInterval;
        this.dynamicIntervalStart = dynamicIntervalStart;
        this.duration = duration;
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        ca = new CachingAlgorithm();
        cme = new CostModelsExp();
        baseline1 = new Baseline1<>();
        clockMap = new ClockHashMap<>();
    }

    public WorkloadGenerator(int regularInterval) {
        this.regularInterval = regularInterval;
        this.dynamicIntervalStart = 0;
        this.duration = 0;
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        ca = new CachingAlgorithm();
        cme = new CostModelsExp();
        baseline1 = new Baseline1<>();
        clockMap = new ClockHashMap<>(3);
    }

    public Duration generateWorkload(int n, List<BEPolicy> policies, List<QueryStatement> queries) {
        int currentTime = 0;
        int nextRegularPolicyInsertionTime = 0;
        int sizeOfPolicies = policies.size();

        int windowSize = 10;
        int generatedQueries = 0;
        int yQuery = 0;
        boolean cachingFlag = false;
        LinkedList<QueryStatement> queryWindow = new LinkedList<>();

//      Bursty State variables
        boolean bursty = true;


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

        String fileName = "fixingQP.txt";

        boolean first = true;

        result.append("No. of policies= "). append(policies.size()).append("\n")
                .append("No. of queries= ").append(queries.size()).append("\n")
                .append("Interleaving Techniques= ").append("[Constant Interval= ").append(regularInterval).append("]")
                .append("[Variable Interval= ").append(dynamicIntervalStart).append(",").append(dynamicIntervalStart+duration).append("]").append("\n");
        writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);

        Instant fsStart = Instant.now();

        if(cachingFlag){
            System.out.println("!!!Caching!!!");
            if(!bursty) {
                System.out.println("!!!Steady!!!");
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
                        if (generatedQueries < 6401) {
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
//                        cme.runAlgorithm(clockHashMap, querier, query, timestampDirectory);
//                baseline1.runAlgorithm(clockHashMap, querier, query, timestampDirectory, countUpdate);
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
                System.out.println("***Bursty State***");
                // Initial values for bursty workload rates
                int policyRate = 500;
                int queryRate = 1;

                while (!queries.isEmpty() && !policies.isEmpty()) {
                    // High policy insertion phase
                    if (currentTime == 0 || currentTime == nextRegularPolicyInsertionTime) {
                        List<BEPolicy> regularPolicies = extractPolicies(policies, policyRate);

                        // Insert policies into the database
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

                    // Steady-state with dynamic query rate
                    for (int i = 0; i < queryRate; i++) {
                        if (generatedQueries < 6376) {
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
                        }
                    }

                    // Writing results to file
                    if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                    else first = false;

                    // Clearing StringBuilder for the next iteration
                    result.setLength(0);

                    currentTime++;

                    // Decrease policy rate and increase query rate gradually
                    policyRate = Math.max(policyRate - 10, 1); // Cap minimum at 1
                    queryRate = Math.min(queryRate + 5, 250); // Cap maximum at 50
                }
            }
        }else{
            System.out.println("!!! Without Caching!!!");
            if(!bursty){
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

                    // Steady State
                    for (int i = 0; i < yQuery; i++) {
                        if (generatedQueries < 15761) {
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
            }else{
                System.out.println("***Bursty State***");
                // Initial values for bursty workload rates
                int policyRate = 500;
                int queryRate = 1;

                while (!queries.isEmpty() && !policies.isEmpty()) {
                    // High policy insertion phase
                    if (currentTime == 0 || currentTime == nextRegularPolicyInsertionTime) {
                        List<BEPolicy> regularPolicies = extractPolicies(policies, policyRate);

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

                    // Steady-state with dynamic query rate
                    for (int i = 0; i < queryRate; i++) {
                        if (generatedQueries < 6376) {
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
                        }
                    }
                    // Writing results to file
                    if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                    else first = false;

                    // Clearing StringBuilder for the next iteration
                    result.setLength(0);

                    currentTime++;

                    // Decrease policy rate and increase query rate gradually
                    policyRate = Math.max(policyRate - 10, 1); // Cap minimum at 1
                    queryRate = Math.min(queryRate + 5, 250); // Cap maximum at 50
                }
            }
        }
        Instant fsEnd = Instant.now();
        Duration totalRunTime = Duration.between(fsStart, fsEnd);
        return totalRunTime;
    }

    public Duration runDemo() {

        Writer writer = new Writer();
        StringBuilder result = new StringBuilder();
        List<BEPolicy> allowPolicies = new ArrayList<>();
        boolean fgacCaching = true;

        System.out.println("Experiment");

        String fileName = "checkingQP.csv";
        result.append("Querier").append(",")
                .append("No. of Policies").append(",")
                .append("Median Generation Time (ms)").append(",")
                .append("Median Execution Time (ms)").append(",")
                .append("Median Policy Retrieval Time (ms)").append("\n");
        writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);

        List<String> queriers = Arrays.asList("1081", "4141", "5833", "9178", "11858",
                "15354", "17798", "18852", "19924", "19963",
                "20011", "23952", "26484", "29699", "31863", "34647");

        boolean first = true;

        Instant fsStart = Instant.now();

        for (String querier : queriers) {
            List<Double> policyRetrievalTimes = new ArrayList<>();
            List<Double> guardGenerationTimes = new ArrayList<>();
            List<Double> executionTimes = new ArrayList<>();

            for (int i = 0; i < 3; i++) {
                // Measure Policy Retrieval Time
                Instant start = Instant.now();
                allowPolicies = polper.retrievePolicies(querier,
                        PolicyConstants.USER_INDIVIDUAL, PolicyConstants.ACTION_ALLOW);
                Instant end = Instant.now();
                double millisecondsPR = Duration.between(start, end).toMillis();
                policyRetrievalTimes.add(millisecondsPR);

                if (allowPolicies == null) return null;
                System.out.println("Querier #: " + querier + " with " + allowPolicies.size() + " allow policies");

                if(fgacCaching == true){
                    // Measure Guard Generation Time
                    start = Instant.now();
                    BEExpression allowBeExpression = new BEExpression(allowPolicies);
                    SelectGuard gh = new SelectGuard(allowBeExpression, true); // Generates guards
                    end = Instant.now();
                    double millisecondGG = Duration.between(start, end).toMillis();
                    guardGenerationTimes.add(millisecondGG);

                    System.out.println(gh.createGuardedQuery(true));
                    System.out.println("Guard Generation time: " + millisecondGG + " ms, Number of Guards: " + gh.numberOfGuards());

                    // Measure Query Execution Time
                    GuardExp guard = gh.create(String.valueOf(querier), "user");
                    String full_query = String.format("");
                    QueryStatement query = new QueryStatement(full_query,1,new Timestamp(System.currentTimeMillis()));
                    start = Instant.now();
                    String answer = e.runGE(querier, query, guard);
                    end = Instant.now();
                    double executionTimeSec = Duration.between(start, end).toMillis(); // Convert to seconds
                    executionTimes.add(executionTimeSec);
                }
                else{
                    String full_query = String.format("");
                    QueryStatement query = new QueryStatement(full_query,1,new Timestamp(System.currentTimeMillis()));
                    start = Instant.now();
                    String answer = e.runBEPolicies(querier,query,allowPolicies);
                    end = Instant.now();
                    double executionTimeSec = Duration.between(start, end).toMillis(); // Convert to seconds
                    executionTimes.add(executionTimeSec);
                }
            }

            // Calculate medians for each operation
            double medianPolicyRetrievalTime = calculateMedian(policyRetrievalTimes);
//            double medianGuardGenerationTime = calculateMedian(guardGenerationTimes);
            double medianGuardGenerationTime = 0;
            double medianExecutionTime = calculateMedian(executionTimes);

            // Log the medians for the querier
            result.append(querier).append(",")
                    .append(allowPolicies.size()).append(",")
                    .append(medianGuardGenerationTime).append(",")
                    .append(medianExecutionTime).append(",")
                    .append(medianPolicyRetrievalTime).append("\n");

            // Writing results to file
            if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
            else first = false;

            // Clearing StringBuilder for the next iteration
            result.setLength(0);
        }

        Instant fsEnd = Instant.now();
        Duration totalRunTime = Duration.between(fsStart, fsEnd);
        return totalRunTime;
    }

    // Inline median calculation function
    private double calculateMedian(List<Double> times) {
        DoubleStream sortedStream = times.stream().sorted().mapToDouble(Double::doubleValue);
        int size = times.size();
        if (size % 2 == 0) {
            return sortedStream.skip(size / 2 - 1).limit(2).average().orElse(0.0);
        } else {
            return sortedStream.skip(size / 2).findFirst().orElse(0.0);
        }
    }



    private List<BEPolicy> extractPolicies(List<BEPolicy> policies, int n) {
         List<BEPolicy> extractedPolicies = new ArrayList<>();
         Random random = new Random();

         for (int i = 0; i < n && !policies.isEmpty(); i++) {
             int randomIndex = random.nextInt(policies.size()); // Generate a random index within the list size
             extractedPolicies.add(policies.remove(randomIndex)); // Remove and add the policy at the random index
         }
         return extractedPolicies;
    }

    public void runExperiment() {
        // generating policies

        CUserGen cUserGen = new CUserGen(1);
        List<CUserGen.User> users = cUserGen.retrieveUserDataForAC();

        CPolicyGen cpg = new CPolicyGen();
//        List<BEPolicy> additionalpolicies = cpg.generatePoliciesPerQueriesforAC(users,10);
        List<BEPolicy> additionalpolicies = cpg.generatePoliciesPerQueriesforAC(users,200);
        System.out.println("Total no. of additional policies: " + additionalpolicies.size());
 
//        List<BEPolicy> policies = cpg.generatePoliciesforAC(users);

         System.out.println("Total number of entries: " + users.size());
//        System.out.println("Total number of policies: " + policies.size());
        System.out.println("Total number of policies: " + additionalpolicies);

//        for (BEPolicy policy : policies) {
//            System.out.println(policy.toString());
//        }
//        System.out.println();

//        int queryCount = 6376;
//        boolean[] templates = {true, true, false, false};
//        List<QueryStatement> queries = new ArrayList<>();
//        for (int i = 0; i < templates.length; i++) {
//            if (templates[i]) queries.addAll(e.getQueries(i+1,queryCount));
//        }

//        System.out.println("Total number of entries: " + users.size());
//        System.out.println("Total number of policies: " + policies.size());
//        System.out.println("Total number of queries: " + queries.size());

//        int regularInterval = 1; // Example regular interval
//        int dynamicInterval = 1; // Example dynamic interval
//        int duration = 3;

        WorkloadGenerator generator = new WorkloadGenerator(regularInterval);
//        WorkloadGenerator generator = new WorkloadGenerator(regularInterval, dynamicInterval, duration);

        int numPoliciesQueries = 0; // Example number of policies/queries to generate each interval
//        Duration totalRunTime = generator.generateWorkload(numPoliciesQueries, policies, queries);
        Duration totalRunTime = generator.runDemo();
        System.out.println("Total Run Time: " + totalRunTime);
    }
}
