import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;

public class Decrypt {

    /* Insert command line arguments in the following order:
    1. KeyStore name
    2. Password for keystore
    3. Alias for private key
    4. Alias for trusted certificate
    5. Program parameters configuration file
    */
    public static void main(String[] args) {

        try {

            if(args.length != 5){
                throw new Exception("invalid number of arguments. Expect 5 arguments, got: " + args.length);
            }

            String keystoreFileName = args[0];
            String password = args[1];
            String aliasPrivateKey = args[2];
            String aliasCert = args[3];
            String programParamsConfigFile = args[4];

            // Load the configuration file and set properties accordingly
            Properties prop = new Properties();
            InputStream is = new FileInputStream(programParamsConfigFile);
            prop.load(is);
            is.close();

            String symAlgorithm = prop.getProperty("symAlgorithm", "AES/CBC/PKCS5Padding");
            String providerSymAlgorithm = prop.getProperty("providerSymAlgorithm", "SunJCE");
            String aSymAlgorithm = prop.getProperty("aSymAlgorithm", "RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            String providerASymAlgorithm = prop.getProperty("providerASymAlgorithm", "SunJCE");
            String keyStoreInstance = prop.getProperty("keyStoreInstance", "PKCS12");
            String keyGeneratorInstance = prop.getProperty("keyGeneratorInstance", "AES");
            String signatureInstance = prop.getProperty("signatureInstance", "SHA1withRSA");
            String encryptedFile = prop.getProperty("encryptedFile", "encrypted.txt");
            String decryptedFile = prop.getProperty("decryptedFile", "decrypted.txt");
            String configFile = prop.getProperty("configFile", "config.properties");

            // Read public and private key from the keystore
            FileInputStream ksFis = new FileInputStream(keystoreFileName);

            KeyStore ks = KeyStore.getInstance(keyStoreInstance);

            ks.load(ksFis, password.toCharArray());

            PrivateKey privateKey = (PrivateKey) ks.getKey(aliasPrivateKey, password.toCharArray());

            // Get the trusted certificate of public key
            Certificate cert = ks.getCertificate(aliasCert);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Load the configuration file and set properties accordingly
            Properties newProp = new Properties();
            InputStream newIs = new FileInputStream(configFile);
            newProp.load(newIs);
            String iv = newProp.getProperty("IV");
            String encryptedSymKey = newProp.getProperty("Encrypted Symmetric Key");
            String dis = newProp.getProperty("Digital Signature");
            
            newIs.close();

            // Create a concrete cipher object with RSA
            Cipher cipherRSA;
            if (providerASymAlgorithm.length() > 0){
                cipherRSA = Cipher.getInstance(aSymAlgorithm, providerASymAlgorithm);
            } else {
                cipherRSA = Cipher.getInstance(aSymAlgorithm);
            }
            // Initialize the cipher with my private key, which loaded from the keystore
            cipherRSA.init(Cipher.DECRYPT_MODE, privateKey);
            // Decrypt the symmetric key using RSA
            SecretKey sKey = new SecretKeySpec(cipherRSA.doFinal(Base64.getDecoder().decode(encryptedSymKey)),
                    keyGeneratorInstance);

            // Create a concrete cipher object with AES in mode CBC
            Cipher cipherAES;
            if (providerSymAlgorithm.length() > 0){
                cipherAES = Cipher.getInstance(symAlgorithm, providerSymAlgorithm);
            } else {
                cipherAES = Cipher.getInstance(symAlgorithm);
            }

            // Initialize the cipher with the symmetric key we generated before for decryption, using the IV
            cipherAES.init(Cipher.DECRYPT_MODE, sKey, new IvParameterSpec(Base64.getDecoder().decode(iv)));

            // Initiate input output streams, and cipher input stream using the cipher object we generated before
            File plainFile = new File(decryptedFile);
            plainFile.createNewFile(); // if file already exists will do nothing
            FileInputStream fis = new FileInputStream(encryptedFile);
            FileOutputStream fos = new FileOutputStream(decryptedFile);
            CipherInputStream cis = new CipherInputStream(fis, cipherAES);

            byte[] buffer = new byte[8];
            int nread;
            while ((nread = cis.read(buffer)) > 0) {
                fos.write(buffer, 0, nread);
            }
            cis.close();
            fos.flush();
            fos.close();
            fis.close();

            // Verifying the encrypted file
            Signature dsa = Signature.getInstance(signatureInstance);
            // Initializing the object with a public key
            dsa.initVerify(publicKey);
            FileInputStream fisCipher = new FileInputStream(encryptedFile);
            byte[] bufferCipher = new byte[8];
            while ((fisCipher.read(bufferCipher)) > 0) {
                dsa.update(bufferCipher);
            }
            boolean verified = dsa.verify(Base64.getDecoder().decode(dis));

            if (!verified){
                String failureMessage = "Decryption failed";
                System.out.println(failureMessage);
                FileWriter myWriter = new FileWriter(decryptedFile);
                myWriter.write(failureMessage);
                myWriter.close();
            } else {
                System.out.println("Decryption Succeeded");
            }

        } catch (Exception e) {
            System.out.println("An error has occurred while trying to encrypt: " + e);
            e.printStackTrace();
        }
    }
}
