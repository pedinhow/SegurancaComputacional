package common;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Classe utilitária para funções de segurança (HMAC, Cifragem).
 * Baseado em pratica-6.4-crc-sha-hmac.pdf [cite: 491-493, 524-545]
 * e requisitos da pratica-offline-1 [cite: 126-127].
 */
public class SecurityUtils {

    private static final String ALGORITMO_HMAC = "HmacSHA256";
    private static final String ALGORITMO_CIFRA = "AES";

    /**
     * Calcula o HMAC-SHA256 de uma mensagem usando uma chave secreta.
     * Baseado no método calcularHmacSha256 de pratica-6.4 [cite: 524-535].
     */
    public static byte[] calcularHmac(byte[] chave, byte[] mensagem) throws Exception {
        Mac mac = Mac.getInstance(ALGORITMO_HMAC);
        SecretKeySpec keySpec = new SecretKeySpec(chave, ALGORITMO_HMAC);
        mac.init(keySpec);
        return mac.doFinal(mensagem);
    }

    /**
     * Verifica um HMAC de forma segura (tempo constante) para evitar timing attacks.
     * Baseado no método checarHmac de pratica-6.4 [cite: 537-545].
     */
    public static boolean checarHmac(byte[] chave, byte[] mensagem, byte[] hmacRecebido) throws Exception {
        byte[] hmacCalculado = calcularHmac(chave, mensagem);

        // Comparação segura em tempo constante
        return MessageDigest.isEqual(hmacCalculado, hmacRecebido);
    }

    /**
     * Cifra uma mensagem (bytes) usando AES com a chave fornecida.
     * (Implementação básica para cumprir o requisito de confidencialidade ).
     */
    public static byte[] cifrar(byte[] chave, byte[] dados) throws Exception {
        // Nota: Para AES, a chave deve ter tamanho específico (16, 24 ou 32 bytes).
        // Esta implementação básica assume que a chaveHMAC será usada e "cortada" para 16 bytes.
        // Em um sistema real, chaves de cifra e de MAC devem ser diferentes e gerenciadas.
        byte[] chaveAes = new byte[16];
        System.arraycopy(chave, 0, chaveAes, 0, Math.min(chave.length, 16));

        SecretKeySpec secretKey = new SecretKeySpec(chaveAes, ALGORITMO_CIFRA);
        Cipher cipher = Cipher.getInstance(ALGORITMO_CIFRA);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(dados);
    }

    /**
     * Decifra uma mensagem (bytes) usando AES com a chave fornecida.
     * (Implementação básica para cumprir o requisito de confidencialidade ).
     */
    public static byte[] decifrar(byte[] chave, byte[] dadosCifrados) throws Exception {
        byte[] chaveAes = new byte[16];
        System.arraycopy(chave, 0, chaveAes, 0, Math.min(chave.length, 16));

        SecretKeySpec secretKey = new SecretKeySpec(chaveAes, ALGORITMO_CIFRA);
        Cipher cipher = Cipher.getInstance(ALGORITMO_CIFRA);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(dadosCifrados);
    }
}
