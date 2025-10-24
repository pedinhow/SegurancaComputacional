package common;

import java.nio.charset.StandardCharsets;

/**
 * Classe utilitária para conversões.
 * Baseado nos exemplos das práticas (ex: pratica-6.0, 6.1, 6.3, 6.4).
 */
public class ConverterUtils {

    /**
     * Converte um array de bytes para sua representação em string hexadecimal.
     * Garante que cada byte seja formatado com dois dígitos hex (ex: 0A, FF).
     * * Baseado no método byte2hex de pratica-6.0 [cite: 8-13]
     * e bytes2Hex de pratica-6.4 [cite: 497-505].
     */
    public static String bytes2Hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            // Usa-se & 0xFF para garantir que o byte seja tratado como unsigned
            // e o formato %02x garante os dois dígitos.
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    public static byte[] hex2Bytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }
}