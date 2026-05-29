// tests/fixtures/safe.java
//
// Benign Java patterns that must produce ZERO findings. These guard against
// false positives in the Java rules (deserialization / CORS / SSRF / CSRF).
import javax.crypto.Cipher;
import org.springframework.web.bind.annotation.CrossOrigin;

public class Safe {
    // Safe: algorithm loaded from config, not a literal
    public void configDrivenCipher(String algorithmFromConfig) throws Exception {
        Cipher.getInstance(algorithmFromConfig); // variable, not a string literal — should NOT fire
    }

    // Safe: readObject() on a custom, non-ObjectInputStream/XMLDecoder receiver.
    // The declared type is a benign deserializer, so no deserialization finding.
    public void customDeserialize(MyCustomSafeDeserializer myCustomSafeDeserializer) {
        myCustomSafeDeserializer.readObject();
    }

    // Safe: a specific, trusted origin — not a wildcard.
    @CrossOrigin(origins = "https://example.com")
    public void specificOrigin() {}

    // Safe: getForObject() on a non-RestTemplate receiver named *Template.
    public void notARestTemplate(MyTemplate myTemplate, String url) {
        myTemplate.getForObject(url, String.class);
    }

    // Safe: a disable() call that is NOT part of a Spring HttpSecurity chain.
    public void notHttpSecurityCsrf(SomeConfig config) {
        myCsrfHelper(config.disable());
    }

    private void myCsrfHelper(Object ignored) {}
}
