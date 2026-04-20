// Safe patterns that java/hardcoded-crypto-algorithm should NOT fire on.
import javax.crypto.Cipher;
import java.security.MessageDigest;

public class SafeCryptoAgility {
    // Safe: algorithm loaded from config, not a literal
    public void configDrivenCipher(String algorithmFromConfig) throws Exception {
        Cipher.getInstance(algorithmFromConfig);
    }

    // Safe: weak algorithms are owned by java/no-weak-crypto, not this rule
    public void weakAlgos() throws Exception {
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("DES");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
