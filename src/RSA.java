import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class RSA {
    public static byte[] encryptRSA(Key key, byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, BadPaddingException {
        Cipher cipher= Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,key);
        return cipher.doFinal(input);
    }

    //Only mistake: not using the opposite key to the one used for encryption
    public static byte[] decryptRSA(Key key,byte[] input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher= Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(input);
    }
}
