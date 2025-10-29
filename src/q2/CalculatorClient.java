package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class CalculatorClient {

    private static final String DIR_HOST = "localhost";
    private static final int DIR_PORT = 12346;

    // Chave secreta COMPARTILHADA
    private static final byte[] SHARED_SECRET_KEY = DirectoryServer.SHARED_SECRET_KEY;

    // Para testar a falha de segurança [cite: 264]
    // private static final byte[] SHARED_SECRET_KEY =
    //    "chave-errada".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("[Cliente Calc] Conectado.");
            System.out.println("Use o formato: <OPERACAO> <n1> <n2> (ex: SOMA 10 20)");
            System.out.println("Operações: SOMA, SUBTRACAO, MULTIPLICACAO, DIVISAO");
            System.out.println("Digite SAIR para fechar.");
            System.out.print("> ");

            String userInput;
            while ((userInput = scanner.nextLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) break;

                String[] commandParts = userInput.split(" ");
                if (commandParts.length < 1) {
                    System.out.print("> ");
                    continue;
                }
                String service = commandParts[0].toUpperCase();

                try {
                    // 1. Descobrir o serviço [cite: 251]
                    String serverAddress = discoverService(service);
                    System.out.println("Serviço '" + service + "' encontrado em: " + serverAddress + " (via Round Robin)");

                    // 2. Executar o cálculo
                    String result = executeCalculation(serverAddress, userInput);
                    System.out.println("Resultado: " + result);

                } catch (Exception e) {
                    System.err.println("Erro durante a operação: " + e.getMessage());
                }
                System.out.print("> ");
            }
            System.out.println("[Cliente Calc] Desconectado.");
        } catch (Exception e) {
            System.err.println("[Cliente Calc] Erro: " + e.getMessage());
        }
    }

    private static String discoverService(String service) throws Exception {
        try (
                Socket socket = new Socket(DIR_HOST, DIR_PORT);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            String command = "DISCOVER " + service;
            sendSecureMessage(out, command, SHARED_SECRET_KEY);

            String response = in.readLine();
            if (response == null) throw new RuntimeException("Servidor de diretório não respondeu.");

            String plainResponse = processSecureResponse(response, SHARED_SECRET_KEY, "DirServer");
            if (plainResponse.startsWith("OK;")) {
                return plainResponse.substring(3); // Retorna o endereço (ex: "localhost:9001")
            } else {
                throw new RuntimeException(plainResponse); // Ex: "ERROR;Serviço não encontrado"
            }
        }
    }

    private static String executeCalculation(String address, String command) throws Exception {
        String[] addressParts = address.split(":");
        String host = addressParts[0];
        int port = Integer.parseInt(addressParts[1]);

        try (
                Socket socket = new Socket(host, port);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            sendSecureMessage(out, command, SHARED_SECRET_KEY);

            String response = in.readLine();
            if (response == null) throw new RuntimeException("Servidor de cálculo não respondeu.");

            String plainResponse = processSecureResponse(response, SHARED_SECRET_KEY, "CalcServer");
            if (plainResponse.startsWith("OK;")) {
                return plainResponse.substring(3); // Retorna o resultado
            } else {
                return plainResponse; // Retorna a mensagem de erro
            }
        }
    }

    // --- Métodos utilitários de segurança ---
    private static void sendSecureMessage(PrintWriter out, String plainMessage, byte[] key) throws Exception {
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(key, data);
        byte[] hmac = SecurityUtils.calculateHmac(key, encryptedData);
        out.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
    }

    private static String processSecureResponse(String receivedLine, byte[] key, String serverName) throws Exception {
        try {
            String[] parts = receivedLine.split("::");
            if (parts.length != 2) throw new SecurityException("Formato de resposta inválido.");
            byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
            byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

            if (!SecurityUtils.checkHmac(key, encryptedData, receivedHmac)) {
                throw new SecurityException("HMAC da resposta inválido (chave errada?).");
            }
            byte[] decryptedData = SecurityUtils.decrypt(key, encryptedData);
            return new String(decryptedData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("[" + serverName + " Resposta] Erro ao processar resposta: " + e.getMessage());
            throw e;
        }
    }
}