package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class RegistryClient {

    private static final String HOST = "localhost";
    private static final int PORT = 12345;

    // Chave secreta COMPARTILHADA
    private static final byte[] SHARED_SECRET_KEY = MiniDNSServer.SHARED_SECRET_KEY;

    // Para testar a falha (descomente a linha abaixo e comente a de cima) [cite: 245]
    // private static final byte[] SHARED_SECRET_KEY =
    //    "chave-do-atacante".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        try (
                Socket socket = new Socket(HOST, PORT);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))
        ) {
            System.out.println("[Cliente Registrador] Conectado ao servidor.");
            System.out.println("Comandos disponíveis: UPDATE <nome> <ip> | SAIR");
            System.out.println("  (Nomes permitidos: servidor1, servidor4, servidor9)");
            System.out.print("> ");

            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) break;

                sendSecureMessage(out, userInput, SHARED_SECRET_KEY);
                String receivedLine = in.readLine();
                if (receivedLine != null) {
                    processSecureResponse(receivedLine, SHARED_SECRET_KEY);
                }
                System.out.print("> ");
            }
            System.out.println("[Cliente Registrador] Desconectado.");
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