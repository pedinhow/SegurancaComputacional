package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class RegistryClient {

    private static final String HOST = "172.17.232.64";
    private static final int PORT = 12345;

    // chave secreta
    // private static final byte[] SHARED_SECRET_KEY = MiniDNSServer.SHARED_SECRET_KEY;

    // para testar a falha TODO descomente
     private static final byte[] SHARED_SECRET_KEY =
        "chave-do-atacante".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        try (
                Socket socket = new Socket(HOST, PORT);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            System.out.println("[Cliente Registrador] Conectado ao servidor.");

            // envia os 3 updates de uma vez
            System.out.println("Enviando atualização para servidor1...");
            sendSecureMessage(out, "UPDATE servidor1 192.168.0.111", SHARED_SECRET_KEY);
            processSecureResponse(in.readLine(), SHARED_SECRET_KEY);
            Thread.sleep(1000);

            System.out.println("Enviando atualização para servidor4...");
            sendSecureMessage(out, "UPDATE servidor4 192.168.0.444", SHARED_SECRET_KEY);
            processSecureResponse(in.readLine(), SHARED_SECRET_KEY);
            Thread.sleep(1000);

            System.out.println("Enviando atualização para servidor9...");
            sendSecureMessage(out, "UPDATE servidor9 192.168.0.999", SHARED_SECRET_KEY);
            processSecureResponse(in.readLine(), SHARED_SECRET_KEY);

            System.out.println("[Cliente Registrador] Atualizações concluídas. Desconectando.");

        } catch (Exception e) {
            System.err.println("[Cliente Registrador] Erro: " + e.getMessage());
        }
    }

    public static void sendSecureMessage(PrintWriter out, String plainMessage, byte[] key) throws Exception {
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(key, data);
        byte[] hmac = SecurityUtils.calculateHmac(key, encryptedData);
        out.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
    }

    private static void processSecureResponse(String receivedLine, byte[] key) {
        try {
            if (receivedLine == null) {
                System.err.println("[Servidor Resposta] Servidor não respondeu.");
                return;
            }
            String[] parts = receivedLine.split("::");
            if (parts.length != 2) {
                System.err.println("[Servidor Resposta] ERRO: Formato inválido.");
                return;
            }
            byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
            byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

            boolean isHmacValid = SecurityUtils.checkHmac(key, encryptedData, receivedHmac);
            if (!isHmacValid) {
                System.err.println("[Servidor Resposta] FALHA DE SEGURANÇA: HMAC inválido.");
                return;
            }

            byte[] decryptedData = SecurityUtils.decrypt(key, encryptedData);
            String message = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("[Servidor Resposta] " + message);
        } catch (Exception e) {
            System.err.println("[Servidor Resposta] Erro ao processar mensagem: " + e.getMessage());
        }
    }
}