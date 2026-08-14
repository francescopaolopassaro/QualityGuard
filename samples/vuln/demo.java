import java.sql.Statement;
import java.security.MessageDigest;

class Vulnerable {
    void run(String input) throws Exception {
        Runtime.getRuntime().exec(input);
        MessageDigest d = MessageDigest.getInstance("MD5");
        Statement s = null;
        s.executeQuery("SELECT * FROM users WHERE id = " + input);
        String password = "hunter2";
    }
}