package common;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

/**
 * Classe utilitária para funções de segurança (HMAC, Cifragem).
 *
 */
public class SecurityUtils {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES";

    /**
     * [cite_start]Calcula o HMAC-SHA256. [cite: 239, 262, 288]
     */
    public static byte[] calculateHmac(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(message);
    }

    /**
     * Verifica um HMAC de forma segura (tempo constante).
     */
    public static boolean checkHmac(byte[] key, byte[] message, byte[] receivedHmac) throws Exception {
        byte[] calculatedHmac = calculateHmac(key, message);
        // Comparação segura em tempo constante
        return MessageDigest.isEqual(calculatedHmac, receivedHmac);
    }

    /**
     * [cite_start]Cifra uma mensagem (bytes) usando AES. [cite: 238, 261, 287]
     */
    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        byte[] aesKey = new byte[16];
        System.arraycopy(key, 0, aesKey, 0, Math.min(key.length, 16));

        SecretKeySpec secretKey = new SecretKeySpec(aesKey, CIPHER_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * [cite_start]Decifra uma mensagem (bytes) usando AES. [cite: 238, 261, 287]
     */
    public static byte[] decrypt(byte[] key, byte[] encryptedData) throws Exception {
        byte[] aesKey = new byte[16];
        System.arraycopy(key, 0, aesKey, 0, Math.min(key.length, 16));

        SecretKeySpec secretKey = new SecretKeySpec(aesKey, CIPHER_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }
}
