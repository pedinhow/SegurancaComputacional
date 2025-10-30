package common;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class SecurityUtils {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES";

    public static byte[] calculateHmac(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(message);
    }

    public static boolean checkHmac(byte[] key, byte[] message, byte[] receivedHmac) throws Exception {
        byte[] calculatedHmac = calculateHmac(key, message);
        // comparação segura em tempo constante
        return MessageDigest.isEqual(calculatedHmac, receivedHmac);
    }

    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        byte[] aesKey = new byte[16];
        System.arraycopy(key, 0, aesKey, 0, Math.min(key.length, 16));

        SecretKeySpec secretKey = new SecretKeySpec(aesKey, CIPHER_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] key, byte[] encryptedData) throws Exception {
        byte[] aesKey = new byte[16];
        System.arraycopy(key, 0, aesKey, 0, Math.min(key.length, 16));

        SecretKeySpec secretKey = new SecretKeySpec(aesKey, CIPHER_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }
}
