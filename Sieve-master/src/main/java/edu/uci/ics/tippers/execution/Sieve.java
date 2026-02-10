package edu.uci.ics.tippers.execution;

import edu.uci.ics.tippers.caching.workload.*;
import edu.uci.ics.tippers.execution.experiments.design.GuardGenExp;
import edu.uci.ics.tippers.common.PolicyConstants;
import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.builder.fluent.Configurations;
import org.apache.commons.configuration2.ex.ConfigurationException;


public class Sieve {

    public static void main(String[] args) {
        PolicyConstants.initialize();
        System.out.println("Running Sieve on " + PolicyConstants.DBMS_CHOICE + " at " + PolicyConstants.DBMS_LOCATION + " with "
                + PolicyConstants.TABLE_NAME.toLowerCase() + " and " + PolicyConstants.getNumberOfTuples() + " tuples");
        runSieve();
    }

    public static void runSieve() {
        boolean QUERY_PERFORMANCE_EXP = false;
        boolean POLICY_SCALER_EXP = false;
        Configurations configs = new Configurations();
        try {
            Configuration datasetConfig = configs.properties("config/general.properties");
            QUERY_PERFORMANCE_EXP = datasetConfig.getBoolean("query_performance");
            POLICY_SCALER_EXP = datasetConfig.getBoolean("policy_scaler");
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
        System.out.println("Test");
        GuardGenExp ggexp = new GuardGenExp();
        ggexp.runExperiment();

//        CUserGen cug =new CUserGen();
//        cug.runExperiment();
//        CPolicyGen cpg = new CPolicyGen();
//        cpg.runExpreriment();

//        CQueryGenAC cqg = new CQueryGenAC();
//        cqg.runExperiment();
           

        int regularInterval = 1; // Example regular interval
//        int dynamicInterval = 1; // Example dynamic interval
//        int duration = 5;
//
//        WorkloadDeletion generator = new WorkloadDeletion(regularInterval);
//        generator.runExperiment();

//        WorkloadGenerator generator = new WorkloadGenerator(regularInterval);
//        generator.runExperiment();

//            WorkloadZipfian generator = new WorkloadZipfian();
//            generator.runExperiment();

//        if(QUERY_PERFORMANCE_EXP) {
//            if(PolicyConstants.DBMS_CHOICE.equalsIgnoreCase(PolicyConstants.PGSQL_DBMS))
//                throw new PolicyEngineException("Query Performance experiments only supported on MySQL");
//            QueryPerformance queryPerformance = new QueryPerformance();
//            queryPerformance.runExperiment();
//        }
//        if(POLICY_SCALER_EXP) {
//            PolicyScaler policyScaler = new PolicyScaler();
//            policyScaler.runExperiment();
//        }
    }
}
