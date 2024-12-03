import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class KeyStoreOperations {

        public static KeyStore getKeyStore(String ksFileName, String ksPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
            File ksFile=new File(ksFileName);

            if(!ksFile.exists()){
                throw new UnsupportedOperationException("File doesn't exist.");
            }

            FileInputStream fis=new FileInputStream(ksFile);

            KeyStore ks=KeyStore.getInstance("pkcs12");
            ks.load(fis,ksPassword.toCharArray());

            fis.close();

            return ks;
        }

        public static void printKSContent(KeyStore ks) throws KeyStoreException {
            if(ks!=null){
                System.out.println("KeyStore content: ");

                Enumeration<String> items=ks.aliases();
                while(items.hasMoreElements()){
                    String item=items.nextElement();

                    System.out.println("Item: "+item);

                    if(ks.isKeyEntry(item)){
                        System.out.println("\t - is a key pair.");
                    }

                    if(ks.isCertificateEntry(item)){
                        System.out.println("\t - is a public key.");
                    }
                }
            }
        }

        public static PublicKey getPublicKey(KeyStore ks, String alias) throws KeyStoreException {
            if(ks!=null && ks.containsAlias(alias)){
                PublicKey pb=ks.getCertificate(alias).getPublicKey();
                return pb;
            }else{
                throw new UnsupportedOperationException("No KS or no alias");
            }
        }

        public static PrivateKey getPrivateKey(KeyStore ks, String alias, String passKs) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
            if(ks!=null && ks.containsAlias(alias) && ks.isKeyEntry(alias)){
                PrivateKey pv= (PrivateKey) ks.getKey(alias,passKs.toCharArray());
                return pv;
            }else{
                throw new UnsupportedOperationException("No KS or NO alias or NOT keypair");
            }
        }

        public static PublicKey getPublicKeyFromX509(String fileName) throws FileNotFoundException, CertificateException {
            File file=new File(fileName);
            if(!file.exists()){
                throw new UnsupportedOperationException("Missing file");
            }

            FileInputStream fis=new FileInputStream(file);
            CertificateFactory certFactory= CertificateFactory.getInstance("X.509");
            X509Certificate x509Cert= (X509Certificate) certFactory.generateCertificate(fis);
            return x509Cert.getPublicKey();
        }

}
