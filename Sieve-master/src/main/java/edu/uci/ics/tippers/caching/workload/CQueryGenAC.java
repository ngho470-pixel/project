package edu.uci.ics.tippers.caching.workload;

import edu.uci.ics.tippers.dbms.mysql.MySQLConnectionManager;
import edu.uci.ics.tippers.execution.experiments.performance.QueryPerformance;
import edu.uci.ics.tippers.generation.policy.WiFiDataSet.PolicyUtil;
import edu.uci.ics.tippers.generation.query.QueryGen;
import edu.uci.ics.tippers.model.policy.TimeStampPredicate;
import edu.uci.ics.tippers.model.query.QueryStatement;
import edu.uci.ics.tippers.persistor.PolicyPersistor;

import java.sql.Connection;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class CQueryGenAC extends QueryGen {
    private Connection connection;

    Random r;
    PolicyPersistor polper;
    PolicyUtil pg;
    CUserGen cug;
    int flag;

    private List<Integer> user_ids;
    private List<String> locations;
    private List<String> user_groups;
    Timestamp start_beg, start_fin;
    private List<Integer> hours;
    private List<Integer> numUsers;

    /*
    This constructor set the default values for query variables.
    For AC: location and user_group can only be classroom
            user_group can only have faculty, students
    For SU: all locations and user_group possible
            user_group can have everybody
     */
    public CQueryGenAC(){
        connection = MySQLConnectionManager.getInstance().getConnection();
        r = new Random();
        polper = PolicyPersistor.getInstance();
        pg = new PolicyUtil();
        cug = new CUserGen(1);

        this.user_ids = new ArrayList<>();
        this.start_beg = pg.getDate("MIN");
        this.start_fin = pg.getDate("MAX");

        this.locations = new ArrayList<>(Arrays.asList("3142-clwa-2019","3142-clwa-2039","3142-clwa-2051","3142-clwa-2059",
                "3142-clwa-2065","3142-clwa-2099","3142-clwa-2209","3142-clwa-2219","3142-clwa-2231","3143-clwa-3039",
                "3143-clwa-3051","3143-clwa-3059","3143-clwa-3099","3143-clwa-3209","3143-clwa-3219","3143-clwa-3231",
                "3144-clwa-4019","3144-clwa-4039","3144-clwa-4051","3144-clwa-4059","3144-clwa-4065","3144-clwa-4099",
                "3144-clwa-4209","3144-clwa-4219","3144-clwa-4231","3145-clwa-5019","3145-clwa-5039","3145-clwa-5051",
                "3145-clwa-5059","3145-clwa-5065","3145-clwa-5099","3145-clwa-5209","3145-clwa-5219","3145-clwa-5231",
                "3146-clwa-6011","3146-clwa-6029","3146-clwa-6049","3146-clwa-6131","3146-clwa-6217"));

        this.user_groups = new ArrayList<>(Arrays.asList("3142-clwa-2019","3142-clwa-2039","3142-clwa-2051","3142-clwa-2059",
                "3142-clwa-2065","3142-clwa-2099","3142-clwa-2209","3142-clwa-2219","3142-clwa-2231","3143-clwa-3039",
                "3143-clwa-3051","3143-clwa-3059","3143-clwa-3099","3143-clwa-3209","3143-clwa-3219","3143-clwa-3231",
                "3144-clwa-4019","3144-clwa-4039","3144-clwa-4051","3144-clwa-4059","3144-clwa-4065","3144-clwa-4099",
                "3144-clwa-4209","3144-clwa-4219","3144-clwa-4231","3145-clwa-5019","3145-clwa-5039","3145-clwa-5051",
                "3145-clwa-5059","3145-clwa-5065","3145-clwa-5099","3145-clwa-5209","3145-clwa-5219","3145-clwa-5231",
                "3146-clwa-6011","3146-clwa-6029","3146-clwa-6049","3146-clwa-6131","3146-clwa-6217"));
        user_groups.addAll(locations);
        user_groups.addAll(new ArrayList<>(Arrays.asList("faculty", "undergrad", "graduate")));
        hours = new ArrayList<>(Arrays.asList(1, 2, 3, 4, 5, 7, 10, 12, 15, 17, 20, 23));
        numUsers = new ArrayList<Integer>(Arrays.asList(10,50,100,150,200,250,300,350,400,420));


    }

    //This query retrieves data based on a specified time range and location(s).
    // Example: SELECT * FROM table
    // WHERE start_date >= 'MIN_DATE' AND start_date <= 'MAX_DATE'
    // AND start_time >= 'START_TIME' AND start_time <= 'END_TIME'
    // AND location_id IN ('loc1', 'loc2', ...)
    // Data of all the people at a given location
    @Override
    public List<QueryStatement> createQuery1(int queryCount) {
        List<QueryStatement> queries = new ArrayList<>();
        int duration = 60;

        for (int numQ = 0; numQ < queryCount; numQ++) {
            // Generate query without considering selectivity
            int locs = r.nextInt(locations.size());
            TimeStampPredicate tsPred = new TimeStampPredicate(pg.getDate("MIN"), 60, "00:00", duration);
            String query = String.format("start_date >= \"%s\" AND start_date <= \"%s\" ",
                    tsPred.getStartDate().toString(), tsPred.getEndDate().toString());
            query += String.format("and start_time >= \"%s\" AND start_time <= \"%s\" ",
                    tsPred.getStartTime().toString(), tsPred.getEndTime().toString());
            List<String> locPreds = new ArrayList<>();
            if (locs > 0) {
                for (int predCount = 0; predCount < locs; predCount++) {
                    locPreds.add(String.valueOf(locations.get(new Random().nextInt(locations.size()))));
                }
            } else {
                // Handle the case where locs is empty
                // For example, you could add a default location:
                locPreds.add("3146-clwa-6217");
            }
            query += "AND location_id IN (";
            query += locPreds.stream().map(item -> "\"" + item + "\"").collect(Collectors.joining(", "));
            query += ")";
            queries.add(new QueryStatement(query, 1, new Timestamp(System.currentTimeMillis())));
            duration += 60;
        }
        return queries;
    }

    //Example: SELECT * FROM table WHERE start_date >= 'MIN_DATE' AND start_date <= 'MAX_DATE'
    // AND start_time >= 'START_TIME' AND start_time <= 'END_TIME'
    // AND user_id IN (id1, id2, ...)
    //This query retrieves data based on a specified time range and user ID(s).
    //Data of all the location a used id was present
    @Override
    public List<QueryStatement> createQuery2(int queryCount) {
        List<QueryStatement> queries = new ArrayList<>();
        List<CUserGen.User> users = cug.retrieveUserDataForAC();
        for (CUserGen.User user: users) {
            user_ids.add(user.getId());
        }

        for (int numQ = 0; numQ < queryCount; numQ++) {
            // Generate query without considering selectivity
            int userCount = numUsers.get(new Random().nextInt(numUsers.size()));
            if (userCount == 0) {
                // Ensure there is at least one user
                userCount = 1;
            }
            TimeStampPredicate tsPred = new TimeStampPredicate(pg.getDate("MIN"), 60, "00:00", 300);
            String query = String.format("start_date >= \"%s\" AND start_date <= \"%s\" ",
                    tsPred.getStartDate().toString(), tsPred.getEndDate().toString());
            query += String.format("and start_time >= \"%s\" AND start_time <= \"%s\" ",
                    tsPred.getStartTime().toString(), tsPred.getEndTime().toString());
            List<Integer> userPreds = new ArrayList<>();
            for (int predCount = 0; predCount < userCount; predCount++) {
                userPreds.add(user_ids.get(new Random().nextInt(user_ids.size())));
            }
            query += "AND user_id IN (";
            query += userPreds.stream().map(String::valueOf).collect(Collectors.joining(", "));
            query += ")";
            queries.add(new QueryStatement(query, 2, new Timestamp(System.currentTimeMillis())));
        }
        return queries;
    }

    //Example: SELECT * FROM table WHERE USER_GROUP_MEMBERSHIP.user_group_id = 'group_id'
    // AND PRESENCE.user_id = USER_GROUP_MEMBERSHIP.user_id AND ...
    // This query retrieves data based on a specified user group and utilizes the results from Type 1 queries.
    @Override
    public List<QueryStatement> createQuery3(int queryNum) {
        List<QueryStatement> queries = new ArrayList<>();
        Random r = new Random();
        String user_group = "undergrad";
        String full_query = String.format("Select PRESENCE.user_id, PRESENCE.location_id, PRESENCE.start_date, " +
                "PRESENCE.start_time, PRESENCE.user_group, PRESENCE.user_profile  " +
                "from PRESENCE, USER_GROUP_MEMBERSHIP " +
                "where USER_GROUP_MEMBERSHIP.user_group_id = \"%s\" AND PRESENCE.user_id = USER_GROUP_MEMBERSHIP.user_id " +
                "AND ", user_group);
        List<QueryStatement> select_queries = createQuery1(queryNum);
        for (QueryStatement qs: select_queries) {
            queries.add(new QueryStatement(full_query + qs.getQuery(), 3, new Timestamp(System.currentTimeMillis())));
        }
        return queries;
    }

    //The previous SIEVE uses 4 query templates, but we'll work with only 3.
    // However, we will still need to override it.
    @Override
    public List<QueryStatement> createQuery4() {
        List<QueryStatement> queries = new ArrayList<>();
        for (int j = 0; j < 200; j++) {
            // Generate query without considering selectivity
            TimeStampPredicate tsPred = new TimeStampPredicate(pg.getDate("MIN"), 60, "00:00", 7 * j);
            String query = String.format("SELECT location_id, COUNT(*) FROM PRESENCE WHERE start_time >= \"%s\" " +
                            "AND start_time <= \"%s\" GROUP BY location_id",
                    tsPred.getStartTime().toString(), tsPred.getEndTime().toString());
            queries.add(new QueryStatement(query, 4, new Timestamp(System.currentTimeMillis())));
        }
        return queries;
    }

    public List<QueryStatement> createQuery1(List<String> selTypes, int numOfQueries){return null;};

    public List<QueryStatement> createQuery2(List<String> selTypes, int numOfQueries){return null;};

    public List<QueryStatement> createQuery3(List<String> selTypes, int numOfQueries){return null;};

    public void runExperiment() {
        CQueryGenAC cqg = new CQueryGenAC();
        QueryPerformance e = new QueryPerformance();
        boolean[] templates = {true, true, false, false};
        int numOfQueries = 3940;
        String querier;
        List<QueryStatement> queries = cqg.constructWorkload(templates, numOfQueries);
        for (QueryStatement query : queries) {
//           System.out.println(query.toString());
           querier = e.runExperiment(query);
           System.out.println("Querier: " + querier);
        }
//        cqg.insertQuery(queries);
        System.out.println();
    }

}
