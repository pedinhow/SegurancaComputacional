package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class QueryClient {

    private static final String HOST = "172.17.232.64";
    private static final int PORT = 12345;

    // chave secreta compartilhada
    private static final byte[] SHARED_SECRET_KEY = MiniDNSServer.SHARED_SECRET_KEY;

    // para testar a falha TODO descomentar
    // private static final byte[] SHARED_SECRET_KEY =
    //    "chave-errada".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        try (
                Socket socket = new Socket(HOST, PORT);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))
        ) {
            System.out.println("[Cliente Requisitante] Conectado ao servidor.");
            Thread listenerThread = new Thread(new ServerListener(in, SHARED_SECRET_KEY));
            listenerThread.start();

            sendSecureMessage(out, "REGISTER_QUERY", SHARED_SECRET_KEY);

            System.out.println("Comandos disponíveis: RESOLVE <nome> | SAIR");
            System.out.print("> ");
            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) break;
                sendSecureMessage(out, userInput, SHARED_SECRET_KEY);
                System.out.print("> ");
            }
            listenerThread.interrupt();
            System.out.println("[Cliente Requisitante] Desconectado.");
        } catch (Exception e) {
            System.err.println("[Cliente Requisitante] Erro: " + e.getMessage());
        }
    }

    public static void sendSecureMessage(PrintWriter out, String plainMessage, byte[] key) throws Exception {
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(key, data);
        byte[] hmac = SecurityUtils.calculateHmac(key, encryptedData);
        out.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
    }
}

class ServerListener implements Runnable {
    private final BufferedReader in;
    private final byte[] sharedKey;

    public ServerListener(BufferedReader in, byte[] key) {
        this.in = in;
        this.sharedKey = key;
    }

    @Override
    public void run() {
        try {
            String receivedLine;
            while (Thread.currentThread().isInterrupted() == false && (receivedLine = in.readLine()) != null) {
                try {
                    String[] parts = receivedLine.split("::");
                    if (parts.length != 2) {
                        System.err.println("\n[Servidor Resposta] ERRO: Formato inválido.");
                        continue;
                    }
                    byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
                    byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

                    boolean isHmacValid = SecurityUtils.checkHmac(sharedKey, encryptedData, receivedHmac);
                    if (!isHmacValid) {
                        System.err.println("\n[Servidor Resposta] FALHA DE SEGURANÇA: HMAC inválido. Mensagem descartada.");
                        continue;
                    }

                    byte[] decryptedData = SecurityUtils.decrypt(sharedKey, encryptedData);
                    String message = new String(decryptedData, StandardCharsets.UTF_8);

                    // imprime a resposta
                    System.out.println(""); // nova linha para a resposta
                    if (message.startsWith("OK;")) {
                        System.out.println("[Servidor Resposta] " + message.substring(3));
                    } else if (message.startsWith("UPDATED;")) {
                        // formato: UPDATED;servidor1;192.168.0.111
                        String[] updateParts = message.split(";");
                        System.out.println("[PUSH_NOTIFICATION] Binding dinâmico: " + updateParts[1] + " agora é " + updateParts[2]);
                    } else {
                        System.out.println("[Servidor Resposta] " + message);
                    }
                    System.out.print("> ");

                } catch (Exception e) {
                    System.err.println("\n[Servidor Resposta] Erro ao processar mensagem: " + e.getMessage());
                }
            }
        } catch (Exception e) {
        }
    }
}