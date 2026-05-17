import java.io.File
import java.net.URL

// Kotlin test fixture — intentionally vulnerable code for foxguard detection tests.

fun sqlInjection(db: Database, userId: String) {
    db.executeQuery("SELECT * FROM users WHERE id = " + userId)
}

fun commandInjection(command: String) {
    Runtime.getRuntime().exec(command)
    ProcessBuilder(command).start()
}

fun unsafeDeserialization(input: java.io.InputStream) {
    val stream = java.io.ObjectInputStream(input)
    stream.readObject()
}

fun ssrf(url: String) {
    URL(url).readText()
}

fun pathTraversal(path: String) {
    File(path).readText()
}

fun weakCrypto(data: ByteArray) {
    java.security.MessageDigest.getInstance("MD5").digest(data)
}

fun hardcodedSecret() {
    val apiKey = "sk-live-abcdef123456789"
    println(apiKey)
}

fun xxe(xml: String) {
    val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
    builder.parse(xml.byteInputStream())
}

fun cors(config: CorsRegistry) {
    config.addMapping("/**").allowedOrigins("*")
}

fun eval(script: String) {
    javax.script.ScriptEngineManager().getEngineByName("js").eval(script)
}

fun taintSql(call: ApplicationCall, db: Database) {
    val id = call.request.queryParameters["id"]
    db.executeQuery("SELECT * FROM users WHERE id = " + id)
}
