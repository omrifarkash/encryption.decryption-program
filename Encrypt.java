import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;

public class Encrypt {

    /* Insert command line arguments in the following order:
    1. Program parameters configuration file
    2. KeyStore name
    3. Password for keystore
    4. Alias for private key
    5. Alias for trusted certificate
    6. File to encrypt
    */
    public static void main(String[] args) {

        try {

            if(args.length != 6){
                throw new Exception("invalid number of arguments. Expect 6 arguments, got: " + args.length);
            }

            String programParamsConfigFile = args[0];
            String keystoreFileName = args[1];
            String password = args[2];
            String aliasPrivateKey = args[3];
            String aliasCert = args[4];
            String fileToEncrypt = args [5];

            // Load the configuration file and set properties accordingly
            Properties prop = new Properties();
            InputStream is = new FileInputStream(programParamsConfigFile);
            prop.load(is);

            String symAlgorithm = prop.getProperty("symAlgorithm", "AES/CBC/PKCS5Padding");
            String providerSymAlgorithm = prop.getProperty("providerSymAlgorithm", "SunJCE");
            String aSymAlgorithm = prop.getProperty("aSymAlgorithm", "RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            String providerASymAlgorithm = prop.getProperty("providerASymAlgorithm", "SunJCE");
            String keyStoreInstance = prop.getProperty("keyStoreInstance", "PKCS12");
            String keyGeneratorInstance = prop.getProperty("keyGeneratorInstance", "AES");
            String signatureInstance = prop.getProperty("signatureInstance", "SHA1withRSA");
            String encryptedFile = prop.getProperty("encryptedFile", "encrypted.txt");
            String configFile = prop.getProperty("configFile", "config.properties");


            // Read public and private key from the keystore
            // Ask the user for the keystore filename
            FileInputStream ksFis = new FileInputStream(keystoreFileName);

            KeyStore ks = KeyStore.getInstance(keyStoreInstance);
            ks.load(ksFis, password.toCharArray());

            PrivateKey privateKey = (PrivateKey) ks.getKey(aliasPrivateKey, password.toCharArray());

            // Get the trusted certificate of public key
            Certificate cert = ks.getCertificate(aliasCert);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Generate a symmetric key for AES
            KeyGenerator kg = KeyGenerator.getInstance(keyGeneratorInstance);
            SecretKey sKey = kg.generateKey();

            Cipher cipherAES;
            // Create a concrete cipher object with AES in mode CBC
            if (providerSymAlgorithm.length() > 0) {
                cipherAES = Cipher.getInstance(symAlgorithm, providerSymAlgorithm);
            } else {
                cipherAES = Cipher.getInstance(symAlgorithm);
            }
            // Generate random IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            // Initialize the cipher with the secret key we generated before for encryption, using the random IV
            cipherAES.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(iv));

            // Initiate input output streams, and cipher output stream using the cipher object we generated before
            File cipherFile = new File(encryptedFile);
            cipherFile.createNewFile(); // if file already exists will do nothing
            FileInputStream fis = new FileInputStream(fileToEncrypt);
            FileOutputStream fos = new FileOutputStream(encryptedFile);
            CipherOutputStream cos = new CipherOutputStream(fos, cipherAES);

            byte[] buffer = new byte[8];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                cos.write(buffer, 0, nread);
            }
            cos.flush();
            cos.close();
            fos.flush();
            fos.close();
            fis.close();

            // Create a concrete cipher object with RSA
            Cipher cipherRSA;
            if (providerASymAlgorithm.length() > 0){
                cipherRSA = Cipher.getInstance(aSymAlgorithm, providerASymAlgorithm);
            } else {
                cipherRSA = Cipher.getInstance(aSymAlgorithm);
            }
            // Initialize the cipher with the public key we loaded from the keystore
            cipherRSA.init(Cipher.ENCRYPT_MODE, publicKey);
            // Encrypt the secret key using RSA
            final byte[] encryptKey = cipherRSA.doFinal(sKey.getEncoded());

            // Signing the encrypted file
            Signature dsa = Signature.getInstance(signatureInstance);
            // Initializing the object with a private key
            dsa.initSign(privateKey);
            FileInputStream fisCipher = new FileInputStream(encryptedFile);
            byte[] bufferCipher = new byte[8];
            while ((fisCipher.read(bufferCipher)) > 0) {
                dsa.update(bufferCipher);
            }
            byte[] sig = dsa.sign();

            // Create a configuration file and set properties accordingly
            Properties configProp = new Properties();
            configProp.setProperty("Encrypted Symmetric Key", Base64.getEncoder().encodeToString(encryptKey));
            configProp.setProperty("IV", Base64.getEncoder().encodeToString(iv));
            configProp.setProperty("Digital Signature", Base64.getEncoder().encodeToString(sig));
            FileWriter fw = new FileWriter(configFile);
            configProp.store(fw, "Configuration file");

            fw.close();

            System.out.println("Encryption Succeeded");

        } catch (Exception e) {
            System.out.println("An error has occurred while trying to encrypt: " + e);
            e.printStackTrace();
        }
    }
}
