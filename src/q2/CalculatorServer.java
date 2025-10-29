package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class CalculatorServer {

    private static final String DIR_HOST = "localhost";
    private static final int DIR_PORT = 12346;
    private final int port;
    private final String myAddress;

    public CalculatorServer(int port) {
        this.port = port;
        this.myAddress = "localhost:" + port;
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Uso: java q2.CalculatorServer <porta>");
            System.exit(1);
        }
        try {
            int port = Integer.parseInt(args[0]);
            CalculatorServer calcServer = new CalculatorServer(port);
            calcServer.registerServices();
            calcServer.startService();
        } catch (NumberFormatException e) {
            System.err.println("Porta inválida: " + args[0]);
        }
    }

    private void registerServices() {
        // Serviços que este servidor oferece [cite: 246]
        String[] services = {"SOMA", "SUBTRACAO", "MULTIPLICACAO", "DIVISAO"};
        System.out.println("[CalcServer-" + port + "] Registrando serviços no Diretório...");

        for (String service : services) {
            try (
                    Socket socket = new Socket(DIR_HOST, DIR_PORT);
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
            ) {
                String command = "REGISTER " + service + " " + myAddress;
                sendSecureMessage(out, command, DirectoryServer.SHARED_SECRET_KEY);

                String response = in.readLine(); // Opcional, apenas para log
                if (response != null) {
                    processSecureResponse(response, DirectoryServer.SHARED_SECRET_KEY, "DirServer");
                }
            } catch (Exception e) {
                System.err.println("[CalcServer-" + port + "] Erro ao registrar " + service + ": " + e.getMessage());
            }
        }
        System.out.println("[CalcServer-" + port + "] Registro concluído.");
    }

    private void startService() {
        System.out.println("[CalcServer-" + port + "] Aguardando clientes de cálculo na porta " + port);
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[CalcServer-" + port + "] Cliente de cálculo conectado: " + clientSocket.getInetAddress());

                // Cria uma nova thread para o cálculo
                CalculationHandler handler = new CalculationHandler(
                        clientSocket,
                        DirectoryServer.SHARED_SECRET_KEY
                );
                Thread clientThread = new Thread(handler);
                clientThread.start();
            }
        } catch (Exception e) {
            System.err.println("[CalcServer-" + port + "] Erro no serviço de cálculo: " + e.getMessage());
        }
    }

    // --- Métodos utilitários de segurança ---
    private void sendSecureMessage(PrintWriter out, String plainMessage, byte[] key) throws Exception {
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(key, data);
        byte[] hmac = SecurityUtils.calculateHmac(key, encryptedData);
        out.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
    }

    private void processSecureResponse(String receivedLine, byte[] key, String serverName) {
        try {
            String[] parts = receivedLine.split("::");
            if (parts.length != 2) return;
            byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
            byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);
            if (!SecurityUtils.checkHmac(key, encryptedData, receivedHmac)) return;
            byte[] decryptedData = SecurityUtils.decrypt(key, encryptedData);
            String message = new String(decryptedData, StandardCharsets.UTF_8);
            System.out.println("[" + serverName + " Resposta] " + message);
        } catch (Exception e) { /* ignora */ }
    }
}