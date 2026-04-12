// Java test fixture — intentionally vulnerable code for foxguard detection tests

import java.io.*;
import java.net.URL;
import java.sql.*;
import javax.xml.parsers.DocumentBuilderFactory;

public class Vulnerable {

    // java/no-sql-injection
    void sqlInjection(String userId) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
        em.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'");
    }

    // java/no-command-injection
    void commandInjection(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        new ProcessBuilder(cmd);
    }

    // java/no-unsafe-deserialization
    void unsafeDeser(InputStream is) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(is);
        ois.readObject();
    }

    // java/no-ssrf
    void ssrf(String url) throws Exception {
        new URL(url);
    }

    // java/no-path-traversal
    void pathTraversal(String path) throws Exception {
        new File(path);
        new FileInputStream(path);
    }

    // java/no-weak-crypto
    void weakCrypto() throws Exception {
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("DES");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    // java/no-hardcoded-secret
    String password = "supersecret123";
    String apiKey = "sk-live-abcdef123456";

    // java/no-xxe
    void xxe() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    }

    // java/spring-csrf-disabled
    void csrf() {
        http.csrf().disable();
    }

    // java/spring-cors-permissive
    void cors() {
        registry.allowedOrigins("*");
    }

    // java/no-xss
    void xss(String userInput, HttpServletResponse response) throws Exception {
        response.getWriter().write(userInput);
        response.getWriter().println(userInput);
        out.write(userInput);
        out.println(userInput);
        PrintWriter pw = response.getWriter();
        pw.write("<h1>" + userInput);
        pw.println("<div>" + userInput);
    }
}
