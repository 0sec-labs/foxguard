import java.io.File
import java.net.URL

// Kotlin safe fixture — should not trigger built-in Kotlin rules.

fun parameterizedSql(db: Database, userId: String) {
    db.executeQuery("SELECT * FROM users WHERE id = ?", userId)
}

fun staticCommand() {
    Runtime.getRuntime().exec("uptime")
    ProcessBuilder("git", "--version").start()
}

fun safeHttp() {
    URL("https://api.example.com/health").readText()
}

fun staticFile() {
    File("config/application.conf").readText()
}

fun strongCrypto(data: ByteArray) {
    java.security.MessageDigest.getInstance("SHA-256").digest(data)
}

fun configuredSecret() {
    val apiKey = System.getenv("API_KEY")
    println(apiKey)
}

fun safeXml() {
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
}

fun cors(config: CorsRegistry) {
    config.addMapping("/api").allowedOrigins("https://example.com")
}

fun noEval(script: String) {
    println(script.length)
}

// readObject() on a non-deserialization receiver — not unsafe deserialization.
fun safeReadObject(mySafe: SafeReader) {
    mySafe.readObject()
}

// Custom header that merely contains the CORS header substring — not a real
// Access-Control-Allow-Origin wildcard.
fun customHeader(response: HttpServletResponse) {
    response.setHeader("X-Access-Control-Allow-Origin", "*")
}

// Parameterized prepared statement with a placeholder, value bound via setString.
fun parameterizedPrepared(conn: Connection, call: ApplicationCall) {
    val id = call.request.queryParameters["id"]
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, id)
}

// Fully literal SQL string — no dynamic operand or interpolation.
fun literalSql(db: Database) {
    db.executeQuery("SELECT * FROM users WHERE active = true")
    db.executeQuery("SELECT " + "id" + " FROM users")
}
