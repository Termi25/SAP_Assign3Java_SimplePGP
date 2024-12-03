import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;

public class DigitalSignature {
        public static byte[] getDigitalSignature(String file, PrivateKey privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            File inputF=new File(file);
            if(!inputF.exists()){
                throw new UnsupportedOperationException("Missing file");
            }

            FileInputStream fis=new FileInputStream(inputF);

            Signature signature=Signature.getInstance("SHA512withRSA");
            signature.initSign(privateKey);
            byte[] buffer=fis.readAllBytes();
            signature.update(buffer);
            fis.close();

            return signature.sign();
        }

        public static boolean isDigitalSignatureValid(String fileName, byte[] signature, PublicKey publicKey) throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
            File inputF=new File(fileName);
            if(!inputF.exists()){
                throw new UnsupportedOperationException("Missing file");
            }

            FileInputStream fis=new FileInputStream(inputF);

            Signature sign=Signature.getInstance("SHA512withRSA");
            sign.initVerify(publicKey);

            sign.update(fis.readAllBytes());

            fis.close();
            return sign.verify(signature);
        }
}