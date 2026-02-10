package edu.uci.ics.tippers.caching.costmodel;

import edu.uci.ics.tippers.caching.CircularHashMap;
import edu.uci.ics.tippers.caching.ClockHashMap;
import edu.uci.ics.tippers.caching.workload.CPolicyGen;
import edu.uci.ics.tippers.caching.workload.CUserGen;
import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.execution.experiments.performance.QueryPerformance;
import edu.uci.ics.tippers.fileop.Writer;
import edu.uci.ics.tippers.model.guard.GuardExp;
import edu.uci.ics.tippers.model.policy.BEPolicy;
import edu.uci.ics.tippers.model.query.QueryStatement;
import edu.uci.ics.tippers.persistor.PolicyPersistor;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public class CMWorkoad {
    PolicyPersistor polper;
    QueryPerformance e;
    CostModelsExp cm;
    ClockHashMap<String, GuardExp> clockMap;

    public CMWorkoad() {
        polper = PolicyPersistor.getInstance();
        e = new QueryPerformance();
        cm = new CostModelsExp<>();
        clockMap = new ClockHashMap<>();
    }

    public Duration generateWorkload(List<BEPolicy> policies, QueryStatement query) {
        int n = 1;
        int currentTime = 0;

        CircularHashMap<String, Timestamp> timestampDirectory = new CircularHashMap<>(3);
        ClockHashMap<String, GuardExp> clockHashMap = new ClockHashMap<>(3);

        Writer writer = new Writer();
        StringBuilder result = new StringBuilder();
        String fileName = "demo.txt";

        boolean first = true;

        result.append("No. of policies= "). append(policies.size()).append("\n")
                .append("No. of queries= ").append(1).append("\n");
        writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
        System.out.println("!!!Regen Vs Update!!!");

        Instant fsStart = Instant.now();

        while (!policies.isEmpty()) {

            int policiesToGenerate = Math.min(n, policies.size());
            List<BEPolicy> regularPolicies = extractPolicies(policies, policiesToGenerate);

            //Insert policy into database
            for(BEPolicy policy: regularPolicies){
                result.append(currentTime).append(",")
                        .append(policy.toString()).append("\n");
                Instant pinsert = Instant.now();
                Timestamp policyinsertionTime = Timestamp.from(pinsert);
                timestampDirectory.put(policy.fetchQuerier(),policyinsertionTime);
                policy.setInserted_at(policyinsertionTime);
            }

            polper.insertPolicy(regularPolicies);

            result.append(currentTime).append(",")
                    .append(query.toString()).append("\n");
            cm.runAlgorithm(clockHashMap, "1040", query, timestampDirectory);


            // Writing results to file
            if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
            else first = false;

            // Clearing StringBuilder for the next iteration
            result.setLength(0);

            currentTime++;
            if (n<=2) n = 2 * n;
            else if (n<=10) n = n + 2;
            else if (n<=100) n = n + 10;
            else n = n + 100;
        }

        Instant fsEnd = Instant.now();
        Duration totalRunTime = Duration.between(fsStart, fsEnd);
        return totalRunTime;
    }

    private List<BEPolicy> extractPolicies(List<BEPolicy> policies, int n) {
        List<BEPolicy> extractedPolicies = new ArrayList<>();
        for (int i = 0; i < n && !policies.isEmpty(); i++) {
            extractedPolicies.add(policies.remove(0)); // Remove and add the first policy from the list
        }
        return extractedPolicies;
    }

    public void runExperiment() {

        CUserGen cUserGen = new CUserGen(1);
        List<CUserGen.User> users = cUserGen.retrieveUserDataForAC();
        Iterator<CUserGen.User> iterator = users.iterator();
        while (iterator.hasNext()) {
            CUserGen.User user = iterator.next();
            if (user.getId() != 958) {
                iterator.remove();
            }
        }

        CPolicyGen cpg = new CPolicyGen();
        List<BEPolicy> policies = cpg.generatePoliciesforAC(users);

        System.out.println("Total number of entries: " + users.size());
        System.out.println("Total number of entries: " + policies.size());

        QueryStatement query = new QueryStatement();
        query.setQuery("start_date >= \"2018-02-01\" AND start_date <= \"2018-04-02\" and start_time >= \"00:00\" " +
                "AND start_time <= \"20:00\" AND location_id IN (\"3142-clwa-2019\")");
        query.setId(1);
        query.setSelectivity(0);
        query.setTemplate(1);

        System.out.println("Total number of entries: " + users.size());
        System.out.println("Total number of policies: " + policies.size());
        System.out.println("Query: " + query.toString());

        CMWorkoad cmw = new CMWorkoad();
        Duration totalRunTime = cmw.generateWorkload(policies, query);
        System.out.println("Total Run Time: " + totalRunTime);
    }
}
