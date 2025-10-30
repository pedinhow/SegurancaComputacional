package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DirectoryHandler implements Runnable {

    private final Socket socket;
    private final Map<String, List<String>> serviceMap;
    private final Map<String, Integer> roundRobinMap;
    private final byte[] sharedKey;

    public DirectoryHandler(Socket socket, Map<String, List<String>> serviceMap, Map<String, Integer> roundRobinMap, byte[] key) {
        this.socket = socket;
        this.serviceMap = serviceMap;
        this.roundRobinMap = roundRobinMap;
        this.sharedKey = key;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String receivedLine;
            while ((receivedLine = in.readLine()) != null) {
                System.out.println("\n[DirHandler] Mensagem recebida (bruta): " + receivedLine);
                try {
                    // decodificar e verificar segurança
                    String[] parts = receivedLine.split("::");
                    if (parts.length != 2) {
                        System.err.println("[DirHandler] ERRO: Formato inválido. Descartando.");
                        continue;
                    }
                    byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
                    byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

                    // verificar HMAC
                    boolean isHmacValid = SecurityUtils.checkHmac(this.sharedKey, encryptedData, receivedHmac);
                    if (!isHmacValid) {
                        System.err.println("[DirHandler] FALHA DE SEGURANÇA: HMAC inválido. Mensagem descartada.");
                        continue; // requisito o servidor deve descartar a mensagem
                    }
                    System.out.println("[DirHandler] HMAC verificado com sucesso.");

                    // decifrar
                    byte[] decryptedData = SecurityUtils.decrypt(this.sharedKey, encryptedData);
                    String command = new String(decryptedData, StandardCharsets.UTF_8);
                    System.out.println("[DirHandler] Comando decifrado: " + command);

                    // processar o comando
                    String response = processCommand(command);

                    // enviar resposta segura
                    sendSecureMessage(out, response, this.sharedKey);

                } catch (Exception e) {
                    System.err.println("[DirHandler] Erro ao processar mensagem: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            // Silencioso
        } finally {
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }

    private String processCommand(String command) {
        String[] parts = command.split(" ");
        String operation = parts[0].toUpperCase();

        switch (operation) {
            case "REGISTER": // enviado por um CalculatorServer
                if (parts.length < 3) return "ERROR;Formato inválido. Use: REGISTER <servico> <host:porta>";
                String service = parts[1].toUpperCase();
                String address = parts[2];
                serviceMap.computeIfAbsent(service, k ->
                        java.util.Collections.synchronizedList(new ArrayList<>())
                ).add(address);
                roundRobinMap.putIfAbsent(service, 0);
                System.out.println("[DirHandler] Serviço registrado: " + service + " em " + address);
                return "OK;Serviço " + service + " registrado em " + address;

            case "DISCOVER":
                if (parts.length < 2) return "ERROR;Formato inválido. Use: DISCOVER <servico>";
                String serviceToFind = parts[1].toUpperCase();
                List<String> servers = serviceMap.get(serviceToFind);
                if (servers == null || servers.isEmpty()) {
                    return "ERROR;Serviço não encontrado: " + serviceToFind;
                }

                // logica do roundrobin
                int index = roundRobinMap.compute(serviceToFind, (k, v) -> (v == null) ? 0 : (v + 1));
                String chosenServer = servers.get(index % servers.size());
                System.out.println("[DirHandler] Descoberta: " + serviceToFind + " -> " + chosenServer + " (Round Robin)");
                return "OK;" + chosenServer;

            default:
                return "ERROR;Comando desconhecido: " + operation;
        }
    }

    private void sendSecureMessage(PrintWriter out, String plainMessage, byte[] key) throws Exception {
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(key, data);
        byte[] hmac = SecurityUtils.calculateHmac(key, encryptedData);
        out.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
    }
}