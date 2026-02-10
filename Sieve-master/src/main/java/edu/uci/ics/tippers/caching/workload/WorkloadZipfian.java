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
public class WorkloadZipfian {
    private int duration;
    PolicyPersistor polper;
    QueryPerformance e;
    CachingAlgorithm ca;
    ClockHashMap<String, GuardExp> clockMap;
    private List<CUserGen.Querier> queriers;
    private int totalQueries;
    private double alpha;

    public WorkloadZipfian (List<CUserGen.Querier> queriers, int totalQueries, double alpha) {
        this.duration = 0;
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        ca = new CachingAlgorithm();
        clockMap = new ClockHashMap<>(3);
        this.queriers = queriers; // List of faculty queries ordered by popularity
        this.totalQueries = totalQueries; // Total number of queries to distribute
        this.alpha = alpha; // Zipfian parameter to control skew
    }

    public WorkloadZipfian () {
        duration = 0;
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        ca = new CachingAlgorithm();
        clockMap = new ClockHashMap<>(3);
        queriers = null; // List of faculty queries ordered by popularity
        totalQueries = 0; // Total number of queries to distribute
        alpha = 0.0; // Zipfian parameter to control skew
    }

    public List<QueryAssignment> assignQueriesUsingZipfian() {
        List<QueryAssignment> queryAssignments = new ArrayList<>();
        int n = queriers.size();

        // Step 1: Calculate the normalizing sum for Zipfian distribution
        double normalizationFactor = 0.0;
        for (int i = 1; i <= n; i++) {
            normalizationFactor += 1.0 / Math.pow(i, alpha);
        }

        // Step 2: Assign queries based on Zipfian frequency
        for (int rank = 1; rank <= n; rank++) {
            CUserGen.Querier querier = queriers.get(rank - 1);  // Get faculty based on rank order
            double probability = (1.0 / Math.pow(rank, alpha)) / normalizationFactor;
            int assignedQueries = (int) Math.round(probability * totalQueries);

            queryAssignments.add(new QueryAssignment(querier, assignedQueries));
        }
        return queryAssignments;
    }

    public Duration generateWorkload(int n, List<BEPolicy> policies, List<QueryStatement> queries) {
        int currentTime = 0;
        int nextRegularPolicyInsertionTime = 0;
        int regularInterval = 1;

        int generatedQueries = 0;
        int yQuery = 5;
        boolean cachingFlag = true;

        QueryStatement query = new QueryStatement();
        Random random = new Random();

        CircularHashMap<String,Timestamp> timestampDirectory = new CircularHashMap<>(194);
        ClockHashMap<String, GuardExp> clockHashMap = new ClockHashMap<>(194);
        HashMap<String,Integer> deletionHashMap = new HashMap<>();

        Writer writer = new Writer();
        StringBuilder result = new StringBuilder();

        String fileName = "Zipfian_C_0_2_50.txt";

        boolean first = true;

        result.append("No. of policies= "). append(policies.size()).append("\n")
                .append("No. of queries= ").append(queries.size()).append("\n");
        writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);

        Instant fsStart = Instant.now();

        WorkloadZipfian generator = new WorkloadZipfian(queriers, totalQueries, alpha);
        List<QueryAssignment> queryAssignments = generator.assignQueriesUsingZipfian();

        for (QueryAssignment assignment : queryAssignments) {
            System.out.println(assignment);
        }

        System.out.println("!!!Zipfian Distribution 0.2 50%!!!");
        if(cachingFlag){
            System.out.println("!!!Caching!!!");
            while (!policies.isEmpty()) {
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
                    // Select the next query based on Zipfian distribution
                    QueryAssignment queryAssignment = selectZipfianQuery(queryAssignments);
                    if (queryAssignment == null) {
                        System.out.println("no more queriers are left to process");
                        break; // Exit if no more queriers are left to process
                    }
                    CUserGen.Querier querier = queryAssignment.querier;
                    if (queries == null || queries.isEmpty()) {
                        return null; // Return null if the list is empty or null
                    }
                    random = new Random();
                    int randomIndex = random.nextInt(queries.size());
                    query = queries.get(randomIndex); // Select and return a random query
                    generatedQueries++;

                    // Record the query for results output
                    result.append(currentTime).append(",").append(query.toString()).append("\n");
                    ca.runAlgorithm(clockHashMap, querier.facultyId, query, timestampDirectory, deletionHashMap);
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

                // Steady State
                for (int i = 0; i < yQuery; i++) {
                    if (generatedQueries < 6401) {
                        // Select the next query based on Zipfian distribution
                        QueryAssignment queryAssignment = selectZipfianQuery(queryAssignments);
                        if (queryAssignment == null) {
                            break; // Exit if no more queries are left to process
                        }
                        CUserGen.Querier querier = queryAssignment.querier;
                        generatedQueries++;

                        // Record the query for results output
                        result.append(currentTime).append(",")
                                .append(query.toString()).append("\n");
//                        querier = e.runExperiment(query);
//                        GuardExp GE = ca.SieveGG(querier, query);
//                        String answer = e.runGE(querier, query, GE);
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

    // Helper method to select queries based on Zipfian distribution
    private QueryAssignment selectZipfianQuery(List<QueryAssignment> zipfianAssignments) {
        // Iterate over the Zipfian assignments and choose queries based on assigned frequencies
        for (QueryAssignment assignment : zipfianAssignments) {
            if (assignment.assignedQueries > 0) {
                assignment.assignedQueries--; // Decrement remaining assigned queries
                return assignment; // Return the selected query
            }
        }
        return null; // Return null if no more queries are left to process (optional handling)
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
        List<BEPolicy> additionalpolicies = cpg.generatePoliciesPerQueriesforAC(users,10);
        System.out.println("Total no. of additional policies: " + additionalpolicies.size());

        List<BEPolicy> policies = cpg.generatePoliciesforAC(users);

        System.out.println("Total number of entries: " + users.size());
        System.out.println("Total number of policies: " + policies.size());

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

        List<CUserGen.Querier> queriers = cUserGen.generateQueriersByPopularity();
        int totalQueries = 15760;
        double alpha = 0.2;

        System.out.println("Total number of entries: " + queriers.size());

        WorkloadZipfian generator = new WorkloadZipfian(queriers, totalQueries, alpha);

        int numPoliciesQueries = 10; // Example number of policies/queries to generate each interval
        Duration totalRunTime = generator.generateWorkload(numPoliciesQueries, policies, queries);
        System.out.println("Total Run Time: " + totalRunTime);
    }

}

class QueryAssignment {
    CUserGen.Querier querier;
    int assignedQueries;

    public QueryAssignment(CUserGen.Querier query, int assignedQueries) {
        this.querier = query;
        this.assignedQueries = assignedQueries;
    }

    @Override
    public String toString() {
        return querier + ", Assigned Queries: " + assignedQueries;
    }
}
