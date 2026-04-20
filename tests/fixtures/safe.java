// tests/fixtures/safe.java
import javax.crypto.Cipher;

public class Safe {
    // Safe: algorithm loaded from config, not a literal
    public void configDrivenCipher(String algorithmFromConfig) throws Exception {
        Cipher.getInstance(algorithmFromConfig); // variable, not a string literal — should NOT fire
    }
}
