package edu.uci.ics.tippers.caching.costmodel;
import java.sql.Connection;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import edu.uci.ics.tippers.caching.CircularHashMap;
import edu.uci.ics.tippers.caching.ClockHashMap;
import edu.uci.ics.tippers.caching.workload.CPolicyGen;
import edu.uci.ics.tippers.caching.workload.CUserGen;
import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.dbms.mysql.MySQLConnectionManager;
import edu.uci.ics.tippers.execution.experiments.performance.QueryPerformance;
import edu.uci.ics.tippers.fileop.Writer;
import edu.uci.ics.tippers.generation.policy.WiFiDataSet.PolicyUtil;
import edu.uci.ics.tippers.model.guard.GenerateCandidate;
import edu.uci.ics.tippers.model.guard.GuardPart;
import edu.uci.ics.tippers.model.guard.SelectGuard;
import edu.uci.ics.tippers.model.policy.BEExpression;
import edu.uci.ics.tippers.model.policy.BEPolicy;
import edu.uci.ics.tippers.model.policy.BooleanPredicate;
import edu.uci.ics.tippers.model.policy.ObjectCondition;
import edu.uci.ics.tippers.model.query.QueryStatement;
import edu.uci.ics.tippers.model.guard.GuardExp;
import edu.uci.ics.tippers.persistor.GuardPersistor;
import edu.uci.ics.tippers.persistor.PolicyPersistor;

public class Baseline1 <C,Q> {
    private Connection connection;
    Random r;
    PolicyPersistor polper;
    GuardPersistor guardPersistor;
    PolicyUtil pg;
    QueryPerformance e;
    Writer writer;
    StringBuilder result;
    String fileName;

    public Baseline1(){
        connection = MySQLConnectionManager.getInstance().getConnection();
        r = new Random();
        polper = PolicyPersistor.getInstance();
        pg = new PolicyUtil();
        this.guardPersistor = new GuardPersistor();
        e = new QueryPerformance();
        writer = new Writer();
        result = new StringBuilder();
        fileName = "ME_B1_S10P1Q.csv";
        result.append("Querier"). append(",")
                .append("Cache log").append("\n");
        writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);

    }

    public void runAlgorithm(ClockHashMap<String, GuardExp> clockHashMap, String querier, QueryStatement query,
                             CircularHashMap<String,Timestamp> timestampDirectory, CircularHashMap<String, Integer> countUpdate) {

        // Implementation of the Guard Caching Algorithm
        int index;

        GuardExp newGE = new GuardExp();

        boolean first = true;

        if(clockHashMap.size == 0){
            index = 0;
        }else{
            index = clockHashMap.getIndex(querier);
        }

        if (index != 0) {
            GuardExp guardExp = clockHashMap.get(querier);
            Timestamp timestampGE = guardExp.getLast_updated();

            Timestamp lastestTimestamp = timestampDirectory.get(querier);

            if (lastestTimestamp != null && lastestTimestamp.before(timestampGE)) {
                clockHashMap.update(querier);

//                Instant fsStart = Instant.now();
//                Duration totalExeTime = Duration.ofMillis(0);
                String answer = e.runGE(querier, query, guardExp);

//                Instant fsEnd = Instant.now();
//                totalExeTime = totalExeTime.plus(Duration.between(fsStart, fsEnd));
//                double seconds = totalExeTime.getSeconds() + totalExeTime.getNano() / 1_000_000.0;

//                System.out.println(answer);
                result.append(querier).append(",")
                        .append("hit").append("\n");
                writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                newGE = guardExp;
            }else{
                List<BEPolicy> newPolicies = fetchNewPolicies(querier, timestampGE);
                Integer updateCount = countUpdate.get(querier);

                int count = 0;

//                Instant fsStart = Instant.now();
//                Duration totalMergeTime = Duration.ofMillis(0);

                for(BEPolicy policy: newPolicies){
                    List<ObjectCondition> policyConditions = policy.getObject_conditions();
                    outerloop:
                    for(ObjectCondition pcondition : policyConditions){
                        for(GuardPart guardPart : guardExp.getGuardParts()){
                            if(pcondition.getAttribute().equals("user_id") && guardPart.getGuard().getAttribute().equals("user_id")){
                                for(BooleanPredicate bp1 : pcondition.getBooleanPredicates()){
                                    for(BooleanPredicate bp2 : guardPart.getGuard().getBooleanPredicates()){
                                        if(bp1.getValue().equals(bp2.getValue())){
                                            count ++;
                                            break outerloop;
                                        }
                                    }
                                }
                            } else if (pcondition.getAttribute().equals("user_group") && guardPart.getGuard().getAttribute().equals("user_group")) {
                                for(BooleanPredicate bp1 : pcondition.getBooleanPredicates()){
                                    for(BooleanPredicate bp2 : guardPart.getGuard().getBooleanPredicates()){
                                        if(bp1.getValue().equals(bp2.getValue())){
                                            count ++;
                                            break outerloop;
                                        }
                                    }
                                }
                            }else if (pcondition.getAttribute().equals("user_profile") && guardPart.getGuard().getAttribute().equals("user_profile")){
                                for(BooleanPredicate bp1 : pcondition.getBooleanPredicates()){
                                    for(BooleanPredicate bp2 : guardPart.getGuard().getBooleanPredicates()){
                                        if(bp1.getValue().equals(bp2.getValue())){
                                            count ++;
                                            break outerloop;
                                        }
                                    }
                                }
                            } else if (pcondition.getAttribute().equals("location_id") && guardPart.getGuard().getAttribute().equals("location_id")) {
                                for(BooleanPredicate bp1 : pcondition.getBooleanPredicates()){
                                    for(BooleanPredicate bp2 : guardPart.getGuard().getBooleanPredicates()){
                                        if(bp1.getValue().equals(bp2.getValue())){
                                            count ++;
                                            break outerloop;
                                        }
                                    }
                                }
                            }else if (pcondition.getAttribute().equals("start_date") && guardPart.getGuard().getAttribute().equals("start_date")) {
                                GenerateCandidate gc = new GenerateCandidate();
                                Boolean flag = gc.mergeability(pcondition, guardPart.getGuard(), policy);
                                if(flag){
                                    count++;
                                    break outerloop;
                                }
                            }
                        }
                    }
                }

//                Instant fsEnd = Instant.now();
//                totalMergeTime = totalMergeTime.plus(Duration.between(fsStart, fsEnd));
//                double secondsM = totalMergeTime.getSeconds() + totalMergeTime.getNano() / 1_000_000.0;

                if(count == newPolicies.size() || (updateCount != null && updateCount >= 10)){

//                    fsStart = Instant.now();
//                    Duration totalGenTime = Duration.ofMillis(0);
                    newGE = SieveGG(querier, query);
//                    fsEnd = Instant.now();
//                    totalGenTime = totalGenTime.plus(Duration.between(fsStart, fsEnd));
//                    double secondsG = totalGenTime.getSeconds() + totalGenTime.getNano() / 1_000_000.0;

                    clockHashMap.put(querier, newGE);

//                    fsStart = Instant.now();
//                    Duration totalExeTime = Duration.ofMillis(0);
//                    String answer = e.runGE(querier, query, newGE);
//                    fsEnd = Instant.now();
//                    totalExeTime = totalExeTime.plus(Duration.between(fsStart, fsEnd));
//                    double secondsE = totalExeTime.getSeconds() + totalExeTime.getNano() / 1_000_000.0;

//                    System.out.println(answer);
                    result.append(querier).append(",")
                            .append("regenerate").append("\n");
                    writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                }else{

                    BEExpression allowBeExpression = new BEExpression(newPolicies);
                    Duration guardGen = Duration.ofMillis(0);
                    Duration totalTime = Duration.ofMillis(0);

                    Instant fsStart = Instant.now();
                    SelectGuard gh = new SelectGuard(allowBeExpression, true);
                    Instant fsEnd = Instant.now();

                    System.out.println(gh.createGuardedQuery(true));
                    guardGen = guardGen.plus(Duration.between(fsStart, fsEnd));
//                    double secondsG = guardGen.getSeconds() + guardGen.getNano() / 1_000_000.0;

                    System.out.println("Guard Generation time: " + guardGen + " Number of Guards: " + gh.numberOfGuards());

                    guardPersistor.insertGuard(gh.create(String.valueOf(querier), "user"));

                    newGE = gh.create(String.valueOf(querier), "user");
                    for (GuardPart gp: newGE.getGuardParts()){
                        guardExp.getGuardParts().add(gp);
                    }
                    clockHashMap.put(querier, guardExp);

//                    fsStart = Instant.now();
                    String answer = e.runGE(querier, query, guardExp);
                    countUpdate.put(querier,updateCount+1);
//                    System.out.println(answer);
//                    Instant totalEnd = Instant.now();
//                    totalTime = totalTime.plus(Duration.between(fsStart, totalEnd));
//                    double secondsE = totalTime.getSeconds() + totalTime.getNano() / 1_000_000.0;
                    result.append(querier).append(",")
                            .append("updation").append("\n");
                    writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
                }
            }
        }else{
            // If querier not found or no matching GE, create a new one
//            Instant fsStart = Instant.now();
//            Duration guardGen = Duration.ofMillis(0);
            newGE = SieveGG(querier, query);
//            Instant fsEnd = Instant.now();
//            guardGen = guardGen.plus(Duration.between(fsStart, fsEnd));
//            double secondsG = guardGen.getSeconds() + guardGen.getNano() / 1_000_000.0;

            if (newGE == null){
                return;
            }else {
                clockHashMap.put(querier, newGE);
//                fsStart = Instant.now();
//                Duration totalExeTime = Duration.ofMillis(0);
//                String answer = e.runGE(querier, query, newGE);
////                System.out.println(answer);
//                fsEnd = Instant.now();
//                totalExeTime = totalExeTime.plus(Duration.between(fsStart, fsEnd));
//                double secondsE = totalExeTime.getSeconds() + totalExeTime.getNano() / 1_000_000.0;
                countUpdate.put(querier,0);
                result.append(querier).append(",")
                        .append("miss").append("\n");
                writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
            }
        }

        // Writing results to file
        if (!first) writer.writeString(result.toString(), PolicyConstants.EXP_RESULTS_DIR, fileName);
        else first = false;

        // Clearing StringBuilder for the next iteration
        result.setLength(0);

        return;

    }

    public GuardExp SieveGG (String querier, QueryStatement query){
        List<BEPolicy> allowPolicies = polper.retrievePolicies(querier,
                PolicyConstants.USER_INDIVIDUAL, PolicyConstants.ACTION_ALLOW);

        if(allowPolicies == null) return null;
        System.out.println("Querier #: " + querier + " with " + allowPolicies.size() + " allow policies");
        BEExpression allowBeExpression = new BEExpression(allowPolicies);
        Duration guardGen = Duration.ofMillis(0);

        Instant fsStart = Instant.now();
        SelectGuard gh = new SelectGuard(allowBeExpression, true);
        Instant fsEnd = Instant.now();

        System.out.println(gh.createGuardedQuery(true));
        guardGen = guardGen.plus(Duration.between(fsStart, fsEnd));

        System.out.println("Guard Generation time: " + guardGen + " Number of Guards: " + gh.numberOfGuards());

        guardPersistor.insertGuard(gh.create(String.valueOf(querier), "user"));

        System.out.println(e.runBEPolicies(querier,query,allowPolicies));

        return gh.create(String.valueOf(querier), "user");
    }
    public List<BEPolicy> fetchNewPolicies(String querier, Timestamp timestampGlobal) {
        // Implementation for fetchNewPolicies function
        List<BEPolicy> allowPolicies = polper.retrievePolicies(querier,
                PolicyConstants.USER_INDIVIDUAL, PolicyConstants.ACTION_ALLOW);
        List<BEPolicy> newPolicies = new ArrayList<>();
        for (BEPolicy policy : allowPolicies) {
            if (policy.getInserted_at().after(timestampGlobal)){
                newPolicies.add(policy);
            }
        }
        return newPolicies; // Placeholder, replace with actual implementation
    }
}
