import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

public class SymmetricKeyGenerator {
    public static byte[] getSymmetricRandomKey(int noBits, String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator=KeyGenerator.getInstance(algorithm);
        keyGenerator.init(noBits);
        return keyGenerator.generateKey().getEncoded();
    }
}
