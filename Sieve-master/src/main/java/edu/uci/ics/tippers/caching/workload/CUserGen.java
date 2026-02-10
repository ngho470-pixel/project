package edu.uci.ics.tippers.caching.workload;

import java.sql.*;
import edu.uci.ics.tippers.dbms.mysql.MySQLConnectionManager;
import java.util.*;

public class CUserGen {

    private Connection connection;
    int flag; //indicates which scenario to run. 1=AC, 2=SU

    public CUserGen(int i) {
        connection = MySQLConnectionManager.getInstance().getConnection();
        flag = i;
    }

    /*
    Sampling users for the attendance control scenario.
    Policy Holders can only be students(undergrad, graduate)
    Querier is faculty
    Location can only be classrooms
    Variable Flag needs to be set as 1
     */
    public List<User> retrieveUserDataForAC() {
        List<User> users = new ArrayList<>();
        try {
            Statement statement = connection.createStatement();
//            ResultSet resultSet = statement.executeQuery("SELECT id, user_id, user_profile, user_group " +
//                    "FROM ashakya.APP_USER WHERE user_profile IN ('graduate', 'undergrad', 'faculty') and " +
//                    "user_group NOT IN ('3143-clwa-3019', '3146-clwa-6122', '3143-clwa-3065', '3146-clwa-6219')");
            ResultSet resultSet = statement.executeQuery("SELECT id, user_id, user_profile, user_group " +
                    "FROM sieve.APP_USER WHERE user_profile IN ('graduate', 'undergrad', 'faculty') and " +
                    "user_group IN ('3146-clwa-6217')");
            while (resultSet.next()) {
                int id = resultSet.getInt("id");
                String userId = resultSet.getString("user_id");
                String userProfile = resultSet.getString("user_profile");
                String userGroup = resultSet.getString("user_group");
                User user = new User(id, userId, userProfile, userGroup);
                users.add(user);
//                count++;
//                System.out.println("Entry #" + count + ": " + user);
            }
//            System.out.println("Total number of entries: " + count);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return users;
    }

    /*
    Sampling users for the space usage scenario.
    Policy Holders can only be anyone
    Querier is faculty or staff
    Location can only be anything except for the forbidden locations
    Variable Flag needs to be set as 2
     */
    public List<User> retrieveUserDataForSU() {
        List<User> users = new ArrayList<>();
        try {
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery("SELECT id, user_id, user_profile, user_group " +
                    "FROM ashakya.APP_USER");
            while (resultSet.next()) {
                int id = resultSet.getInt("id");
                String userId = resultSet.getString("user_id");
                String userProfile = resultSet.getString("user_profile");
                String userGroup = resultSet.getString("user_group");
                User user = new User(id, userId, userProfile, userGroup);
                users.add(user);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return users;
    }

    // Method to retrieve faculty data with student counts for query generation
    public List<Querier> generateQueriersByPopularity() {
        List<Querier> queries = new ArrayList<>();
        try {
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(
                    "SELECT f.id AS faculty_id, COUNT(s.id) AS student_count " +
                            "FROM ashakya.APP_USER f " +
                            "JOIN ashakya.APP_USER s ON f.user_group = s.user_group " +
                            "WHERE f.user_profile = 'faculty' " +
                            "AND s.user_profile IN ('graduate', 'undergrad') " +
                            "AND f.user_group NOT IN ('3143-clwa-3019', '3146-clwa-6122', '3143-clwa-3065', '3146-clwa-6219') " +
                            "GROUP BY f.id, f.user_group " +
                            "ORDER BY student_count DESC");

            while (resultSet.next()) {
                String facultyId = resultSet.getString("faculty_id");
                int studentCount = resultSet.getInt("student_count");

                // Generate a query for this faculty based on their popularity
                Querier query = new Querier(facultyId, studentCount);
                queries.add(query);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return queries;
    }


    public void printUserData(List<User> users) {
        System.out.println("User Data:");
        for (User user : users) {
            System.out.println(user);
        }
        System.out.println("Total number of entries: " + users.size());
    }

    public void runExperiment() {
        CUserGen cug = new CUserGen(1);
        List<User> users;
        if( cug.flag == 1) {
            users = cug.retrieveUserDataForAC();
        } else {
            users = cug.retrieveUserDataForSU();
        }
        cug.printUserData(users);
    }

    public static class User {
        private int id;
        private String userId;
        private String userProfile;
        private String userGroup;

        public User(int id, String userId, String userProfile, String userGroup) {
            this.id = id;
            this.userId = userId;
            this.userProfile = userProfile;
            this.userGroup = userGroup;
        }

        // Getters and setters
        public int getId() {
            return id;
        }
        public String getUserId(){ return userId; }
        public String getUserProfile(){ return userProfile; }
        public String getUserGroup(){ return userGroup; }

        @Override
        public String toString() {
            return "User{" +
                    "id=" + id +
                    ", userId='" + userId + '\'' +
                    ", userProfile='" + userProfile + '\'' +
                    ", userGroup='" + userGroup + '\'' +
                    '}';
        }
    }

    public static class Querier {
        String facultyId;
        int studentCount;

        public Querier(String facultyId, int studentCount) {
            this.facultyId = facultyId;
            this.studentCount = studentCount;
        }

        @Override
        public String toString() {
            return "Faculty ID: " + facultyId + ", Student Count: " + studentCount;
        }
    }
}
