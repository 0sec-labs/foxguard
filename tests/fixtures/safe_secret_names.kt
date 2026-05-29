// Benign names containing secret-keyword substrings, or low-signal
// keywords with env-sourced values. None should be flagged by
// kt/no-hardcoded-secret after the word-boundary + value-gate fix.
object SafeSecretNames {
    // Substring false positives.
    val author = "Pallets"
    val authors = "core team"
    val authenticated = "yes"
    val authorizationScheme = "Bearer"
    val tokenizer = "bert-base-uncased"
    val secretarialNote = "filed"

    fun load() {
        // Low-signal + secret-named values, all env-sourced (not literals).
        val auth = System.getenv("AUTH")
        val token = System.getenv("TOKEN")
        val password = System.getenv("PW")
        val apiKey = System.getenv("API_KEY")
        val secretKey = System.getenv("SECRET_KEY")
        println(auth + token + password + apiKey + secretKey)
    }
}
