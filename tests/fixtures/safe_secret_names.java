// Benign names containing secret-keyword substrings, or low-signal
// keywords with env-sourced values. None should be flagged by
// java/no-hardcoded-secret after the word-boundary + value-gate fix.
public class SafeSecretNames {
    // Substring false positives.
    static final String author = "Pallets";
    static final String authors = "core team";
    static final String authenticated = "yes";
    static final String authorizationScheme = "Bearer";
    static final String tokenizer = "bert-base-uncased";
    static final String secretarialNote = "filed";

    static void load() {
        // Low-signal + secret-named values, all env-sourced (not literals).
        String auth = System.getenv("AUTH");
        String token = System.getenv("TOKEN");
        String password = System.getenv("PW");
        String apiKey = System.getenv("API_KEY");
        String secretKey = System.getenv("SECRET_KEY");
        System.out.println(auth + token + password + apiKey + secretKey);
    }
}
