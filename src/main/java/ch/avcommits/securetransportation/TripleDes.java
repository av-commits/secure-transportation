package ch.avcommits.securetransportation;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class TripleDes {
    private final static MessageDigest md;
    static {
        try {
            md = MessageDigest.getInstance("md5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(String message, byte[] key8byte) {
        try {
            final byte[] digestOfPassword = md.digest(key8byte);
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0, k = 16; j < 8; ) {
                keyBytes[k++] = keyBytes[j++];
            }
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
            final byte[] ivByte = SecureRandom.getSeed(8);
            outputStream.write(ivByte);
            final IvParameterSpec iv = new IvParameterSpec(ivByte);
            final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            final byte[] plainTextBytes = message.getBytes(StandardCharsets.UTF_8);
            outputStream.write(cipher.doFinal(plainTextBytes));

            return outputStream.toByteArray();
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(byte[] message, byte[] key8byte) {
        try {
            final MessageDigest md = MessageDigest.getInstance("md5");
            final byte[] digestOfPassword = md.digest(key8byte);
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0, k = 16; j < 8; ) {
                keyBytes[k++] = keyBytes[j++];
            }

            ByteArrayInputStream inputStream = new ByteArrayInputStream(message);

            final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
            final IvParameterSpec iv = new IvParameterSpec(inputStream.readNBytes(8));
            final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, key, iv);

            final byte[] plainText = decipher.doFinal(inputStream.readAllBytes());

            return new String(plainText, StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IOException e) {
            throw new RuntimeException(e);
        }
    }

}
