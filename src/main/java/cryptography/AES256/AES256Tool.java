package main.java.cryptography.AES256;

import main.java.cryptography.CryptoTool;
import main.java.cryptography.utils.CryptoUtils;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

import static java.nio.charset.StandardCharsets.UTF_8;


public class AES256Tool implements CryptoTool {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTE = 12;
    private static final int TAG_LENGTH_BYTE = 128;


    // AES-GCM needs GCMParameterSpec
    private static byte[] encryptText(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BYTE, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;

    }
    // prefix IV length + IV bytes to cipher text
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {

        byte[] cipherText = encryptText(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;

    }
    /**
     * Encrypt a value and generate a keyfile.
     * If the keyfile is not found, then a new one will be created.
     *
     * @throws GeneralSecurityException
     * @throws IOException if an I/O error occurs
     * @return
     */
    public static byte[] encrypt(byte[] value, File keyFile)
            throws Exception {
        SecretKey secretKet = CryptoUtils.generateAESKey(keyFile);
        return encrypt(value, secretKet, CryptoUtils.getRandomNonce(IV_LENGTH_BYTE));

    }


    private static String decryptText(byte[] cText, SecretKey secret, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BYTE, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, UTF_8);

    }

    /**
     * Decrypt a value.
     *
     * @throws GeneralSecurityException
     * @throws IOException if an I/O error occurs
     */
    public static String decrypt(byte[] message, File keyFile)
            throws Exception {
       return decrypt(message, CryptoUtils.getAESKey(keyFile));
    }


    public static String decrypt(byte[] cText, SecretKey secret) throws Exception {

        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        String plainText = decryptText(cipherText, secret, iv);
        return plainText;

    }
    public static void main(String[] args) throws Exception {

        String OUTPUT_FORMAT = "%-30s:%s";

        String pText = "a";


        File secretFile = new File("C:\\Work\\PLAT20\\test_secret\\secret.secret");

       byte[] encryptedText = AES256Tool.encrypt(pText.getBytes(UTF_8), secretFile);
        System.out.println("\n------ AES GCM Encryption with new File------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)",CryptoUtils.hex(CryptoUtils.readKeyFile(secretFile))));
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) ", CryptoUtils.hex(encryptedText)));
//byte[] encryptedText = CryptoUtils.toByte("5ca9b9e847e36923e394e6732538388adb3efe8cf24356d3e0e7c6108e");
        System.out.println("\n------ AES GCM Decryption with new File------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (hex)", CryptoUtils.hex(encryptedText)));
        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(CryptoUtils.readKeyFile(secretFile))));

        String decryptedText = AES256Tool.decrypt(encryptedText, secretFile);

        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));
    }

}
