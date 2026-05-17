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
