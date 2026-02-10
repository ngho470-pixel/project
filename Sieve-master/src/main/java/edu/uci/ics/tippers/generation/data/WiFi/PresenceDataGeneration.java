package edu.uci.ics.tippers.generation.data.WiFi;

import com.opencsv.CSVReader;
import edu.uci.ics.tippers.common.PolicyConstants;
import edu.uci.ics.tippers.dbms.mysql.MySQLConnectionManager;
import org.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.Date;

public class PresenceDataGeneration {

    private static final String dataDir = "/metadata/";
    private Connection connection;
    private HashMap<Integer, String> user_id_map;

    public PresenceDataGeneration(){
        this.connection = MySQLConnectionManager.getInstance().getConnection();
        try {
            this.connection.setAutoCommit(true);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        this.user_id_map = new HashMap<>();
    }

    private void getAllUsers() {
        PreparedStatement queryStm = null;
        try {
            queryStm = connection.prepareStatement("SELECT ID, USER_ID as id, user_id " +
                    "FROM APP_USER");
            ResultSet rs = queryStm.executeQuery();
            while (rs.next()) user_id_map.put(rs.getInt("id"), rs.getString("user_id"));
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void readCoverage(){
        try{
            BufferedReader br = new BufferedReader (new InputStreamReader(
                    this.getClass().getResourceAsStream( dataDir + DataFiles.COVERAGE.getPath())));
            String st;
            while ((st = br.readLine()) != null) {
                if(st.startsWith("3")){
                    String[] arr = st.split("\\|");
                    String[] roomsWithSpace = arr[1].split(",");
                    List<String> rooms = new ArrayList<String>();
                    for (String r: roomsWithSpace){
                        if (r.startsWith(" "))
                            rooms.add(r.substring(1));
                        rooms.add(r);
                    }
                    String[] rs = new String[rooms.size()];
                    rs = rooms.toArray(rs);
                }
            }
        }
        catch (IOException io) {
            io.printStackTrace();
        }
    }

    private Timestamp parseTimeStamp(String ts){
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        Date parsedDate = null;
        try {
            parsedDate = dateFormat.parse(ts);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return new Timestamp(parsedDate.getTime());
    }

    private Date parseDate(String dateStr) throws ParseException {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
        return dateFormat.parse(dateStr);
    }

    private Date parseTime(String timeStr) throws ParseException {
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
        return timeFormat.parse(timeStr);
    }

    private void parseAndWrite(String fileName) {
        String pInsert = "INSERT INTO PRESENCE " +
                "(USER_ID, LOCATION_ID, USER_PROFILE, USER_GROUP, START_DATE, START_TIME) " +
                "VALUES (?, ?, ?, ?, ?, ?)";
        int presenceCount = 0;
        try {
            InputStream in = getClass().getResourceAsStream(fileName);
            InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8);
            CSVReader csvReader = new CSVReader(reader, ',', '"', 1);
            String[] nextRecord;
            PreparedStatement presenceStmt = connection.prepareStatement(pInsert);
            while ((nextRecord = csvReader.readNext()) != null) {
                Random rand = new Random();
                int userId;
                java.sql.Date startDate;
                java.sql.Time startTime;
                String location;
                String user_profile;
                String user_group;
                if(nextRecord.length == 6){
                    userId = Integer.parseInt(nextRecord[5]);
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    user_group = nextRecord[5];
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    user_profile = nextRecord[5];
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    String concatenateEntry = nextRecord[5];
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    concatenateEntry = concatenateEntry + " " + nextRecord[5];
                    Timestamp ts = parseTimeStamp(concatenateEntry);
                    startDate = new java.sql.Date(ts.getTime());
                    startTime = new java.sql.Time(ts.getTime());
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    location = nextRecord[5];
                    csvReader.readNext();
                }
                else{
                    userId = Integer.parseInt(nextRecord[5]);
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    user_group = nextRecord[5];
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    user_profile = nextRecord[5];
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    Timestamp ts = parseTimeStamp(nextRecord[5]);
                    startDate = new java.sql.Date(ts.getTime());
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    startTime = new java.sql.Time(ts.getTime());
                    csvReader.readNext();
                    nextRecord = csvReader.readNext();
                    location = nextRecord[5];
                    csvReader.readNext();
                }
                presenceStmt.setInt(1, userId);
                presenceStmt.setString(2, location);
                presenceStmt.setString(3, user_profile);
                presenceStmt.setString(4, user_group);
                presenceStmt.setDate(5, startDate);
                presenceStmt.setTime(6, startTime);
                presenceStmt.addBatch();
                presenceCount++;
                if (presenceCount % PolicyConstants.BATCH_SIZE_INSERTION == 0) {
                    presenceStmt.executeBatch();
                    System.out.println("# " + presenceCount + " inserted");
//                    presenceStmt.close(); // needed for postgres
                }
            }
            presenceStmt.executeBatch();
            presenceStmt.close();
        } catch (IOException | SQLException e) {
            e.printStackTrace();
        }
    }

    public void runExperiment() {
//        String csvFilePath = "/results/policy.csv";
        PresenceDataGeneration pdg = new PresenceDataGeneration();
        pdg.getAllUsers();
//        pdg.parseAndWrite(csvFilePath);
        pdg.parseAndWrite(dataDir + DataFiles.PRESENCE_REAL.getPath());
    }
}
