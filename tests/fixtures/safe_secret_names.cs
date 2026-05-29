// Benign names containing secret-keyword substrings, or low-signal
// keywords with env-sourced values. None should be flagged by
// cs/no-hardcoded-secret after the word-boundary + value-gate fix.
using System;

public class SafeSecretNames
{
    // Substring false positives.
    const string author = "Pallets";
    const string authors = "core team";
    const string authenticated = "yes";
    const string authorizationScheme = "Bearer";
    const string tokenizer = "bert-base-uncased";
    const string secretarialNote = "filed";

    static void Load()
    {
        // Low-signal + secret-named values, all env-sourced (not literals).
        string auth = Environment.GetEnvironmentVariable("AUTH");
        string token = Environment.GetEnvironmentVariable("TOKEN");
        string password = Environment.GetEnvironmentVariable("PW");
        string apiKey = Environment.GetEnvironmentVariable("API_KEY");
        string connectionString = Environment.GetEnvironmentVariable("CONN");
        Console.WriteLine(auth + token + password + apiKey + connectionString);
    }
}
