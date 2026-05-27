import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.sql.PreparedStatement;

class SafeJavaTaint {
    void sql(@RequestParam String name, PreparedStatement stmt) throws Exception {
        stmt.setString(1, name);
        stmt.executeQuery();
    }

    void command(HttpServletRequest request) throws Exception {
        String command = request.getParameter("cmd");
        Runtime.getRuntime().exec("id");
    }

    void ssrf(HttpServletRequest req) throws Exception {
        String target = req.getParameter("url");
        new URL("https://example.com/health");
    }

    void deserialize(HttpServletRequest request) throws Exception {
        InputStream input = request.getInputStream();
        ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(new byte[0]));
        stream.readObject(); // foxguard: ignore[java/no-unsafe-deserialization]
    }
}
