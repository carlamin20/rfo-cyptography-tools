package main.java.cryptography.utils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class CryptoUtils {
    public static final String AES = "AES";
    public static final int SK_LENGTH_BIT = 128;

    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // AES secret key
    public static SecretKey generateAESKey(int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }

    public static SecretKey generateAESKey(File keyFile) throws Exception {
        if(keyFile.exists()) throw new Exception("The file already exists!");
        SecretKey secretKey;
        secretKey = CryptoUtils.generateAESKey(SK_LENGTH_BIT);

        FileWriter fw = new FileWriter(keyFile, false);
        fw.write(hex(secretKey.getEncoded()));
        fw.flush();
        fw.close();

        return secretKey;
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static byte[] toByte(String hex){
        return new BigInteger(hex,16).toByteArray();
    }
    public static SecretKey getAESKey(File keyFile) throws FileNotFoundException {
        byte[] keyValue = readKeyFile(keyFile);
        SecretKey aesKey = new SecretKeySpec(keyValue, AES);
        return aesKey;
    }


    public static byte[] readKeyFile(File keyFile)
            throws FileNotFoundException {
        Scanner scanner = new Scanner(keyFile);
        String keyValue = scanner.next();
        scanner.close();

        return toByte(keyValue);
    }
}
