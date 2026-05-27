import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.sql.PreparedStatement;
import java.sql.Statement;

class AccountController {
    private final Statement statement;
    private final PreparedStatement preparedStatement;

    AccountController(Statement statement, PreparedStatement preparedStatement) {
        this.statement = statement;
        this.preparedStatement = preparedStatement;
    }

    String find(@RequestParam String name) throws Exception {
        String where = "name = '" + name + "'";
        String sql = "SELECT * FROM users WHERE " + where;
        return statement.executeQuery(sql).toString();
    }

    void runExport(HttpServletRequest request) throws Exception {
        String report = request.getParameter("report");
        String command = "/usr/local/bin/export " + report;
        Runtime.getRuntime().exec(command); // foxguard: ignore[java/no-command-injection]
    }

    String proxy(HttpServletRequest req) throws Exception {
        String url = req.getParameter("url");
        URL target = new URL(url); // foxguard: ignore[java/no-ssrf]
        return target.toString();
    }

    Object importSnapshot(HttpServletRequest request) throws Exception {
        InputStream input = request.getInputStream();
        ObjectInputStream stream = new ObjectInputStream(input);
        return stream.readObject(); // foxguard: ignore[java/no-unsafe-deserialization]
    }

    // NEAR MISS: request input is bound as a parameter, not concatenated.
    String safeFind(@RequestParam String name) throws Exception {
        preparedStatement.setString(1, name);
        return preparedStatement.executeQuery().toString();
    }

    // NEAR MISS: request input is read but a fixed command is executed.
    void safeExport(HttpServletRequest request) throws Exception {
        String ignored = request.getParameter("report");
        Runtime.getRuntime().exec("/usr/local/bin/export daily");
    }

    // NEAR MISS: request input is read but a fixed allowlisted URL is used.
    String safeProxy(HttpServletRequest req) throws Exception {
        String ignored = req.getParameter("url");
        URL target = new URL("https://api.example.com/health");
        return target.toString();
    }

    // NEAR MISS: request body is read but the deserializer receives fixed bytes.
    Object safeImport(HttpServletRequest request) throws Exception {
        InputStream ignored = request.getInputStream();
        ObjectInputStream stream = new ObjectInputStream(
            new java.io.ByteArrayInputStream(new byte[0])
        );
        return stream.toString();
    }
}
