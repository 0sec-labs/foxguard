import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.sql.Statement;

class VulnerableJavaTaint {
    void sql(@RequestParam String name, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        stmt.executeQuery(query);
    }

    void command(HttpServletRequest request) throws Exception {
        String command = request.getParameter("cmd");
        Runtime.getRuntime().exec(command); // foxguard: ignore[java/no-command-injection]
    }

    void ssrf(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        new URL(target); // foxguard: ignore[java/no-ssrf]
    }

    void deserialize(HttpServletRequest request) throws Exception {
        InputStream input = request.getInputStream();
        ObjectInputStream stream = new ObjectInputStream(input);
        stream.readObject(); // foxguard: ignore[java/no-unsafe-deserialization]
    }
}
