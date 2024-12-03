import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class Main {

    //Command for generating key pair:
    //keytool.exe -genkey -keyalg RSA -alias termikey -keypass passtrm -storepass passks -keystore keystore.ks -dname "cn=Rusu Marius Ioan, ou=Rusu Marius Ioan, o=Rusu Marius Ioan, c=RO"

    public static void main(String[] args) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException {

        KeyStore ks= KeyStoreOperations.getKeyStore("keystore.ks","passks");
        
        PublicKey profPK=KeyStoreOperations.getPublicKey(ks,"simplepgpism");
        KeyStoreOperations.printKSContent(ks);
        System.out.println("\n-----------------------");
        File root=new File(".");

        int i=0;
        System.out.println("Checking received files");
        System.out.println("-----------------------");
        for(File item:root.listFiles()){
            if(item.isFile() && item.getName().endsWith(".txt")){
                if(!item.getName().equals("SAPExamSubjectResponseRusuMariusIoan.txt")){
                    File signFile=new File(item.getName().replace(".txt",".signature"));
                    if((!signFile.exists())){
                        throw new UnsupportedOperationException("Correponding signature missing for the following file: "+item.getName());
                    }
                    FileInputStream fis=new FileInputStream(signFile);

                    i++;
                    if(DigitalSignature.isDigitalSignatureValid(item.getName(),fis.readAllBytes(), profPK)){
                        System.out.println(i+"\t"+item.getName()+" is VALID.");
                    }else{
                        System.out.println(i+"\t"+item.getName()+" is INVALID.");
                    }
                    fis.close();
                }
            }
        }
        System.out.println("-----------------------");

        byte[] randomAESKey=SymmetricKeyGenerator.getSymmetricRandomKey(128,"AES");
        byte[] encryptedAESKey=RSA.encryptRSA(profPK,randomAESKey);
        saveByteArrayToFile(encryptedAESKey,"aes_key.sec");

        AES_wECB.encrypt("SAPExamSubjectResponseRusuMariusIoan.txt","response.sec",randomAESKey);
        PrivateKey userPVK=KeyStoreOperations.getPrivateKey(ks,"termikey","passks");

        saveByteArrayToFile(DigitalSignature.getDigitalSignature("response.sec",userPVK),"signature.ds");
        System.out.println("Encrypted Files: aes_key.sec, response.sec, signature.ds");
        System.out.println("-----------------------");
    }

    public static void saveByteArrayToFile(byte[] byteArray,String pathName) throws IOException {
        File randomAESKeyFile=new File(pathName);
        if(!randomAESKeyFile.exists()){
            randomAESKeyFile.createNewFile();
        }

        FileOutputStream fos=new FileOutputStream(randomAESKeyFile);
        fos.write(byteArray);
        fos.close();
    }

}
