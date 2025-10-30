package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

public class ClientHandler implements Runnable {

    private final Socket socket;
    private final Map<String, String> dnsMap;
    private final List<PrintWriter> subscribers;
    private PrintWriter outputWriter;
    private final byte[] sharedKey;

    public ClientHandler(Socket socket, Map<String, String> dnsMap, List<PrintWriter> subscribers, byte[] key) {
        this.socket = socket;
        this.dnsMap = dnsMap;
        this.subscribers = subscribers;
        this.sharedKey = key;
    }

    @Override
    public void run() {
        try (
                BufferedReader inputReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter outputWriter = new PrintWriter(socket.getOutputStream(), true)
        ) {
            this.outputWriter = outputWriter;
            String receivedLine;

            while ((receivedLine = inputReader.readLine()) != null) {
                System.out.println("\n[Handler] Mensagem recebida (bruta): " + receivedLine);
                try {
                    // decodificar a mensagem (formato: hmacHex::cifraHex)
                    String[] parts = receivedLine.split("::");
                    if (parts.length != 2) {
                        System.err.println("[Handler] ERRO: Formato da mensagem inválido. Descartando.");
                        continue;
                    }
                    byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
                    byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

                    // verificar HMAC
                    boolean isHmacValid = SecurityUtils.checkHmac(this.sharedKey, encryptedData, receivedHmac);
                    if (!isHmacValid) {
                        System.err.println("[Handler] FALHA DE SEGURANÇA: HMAC inválido. Mensagem descartada.");
                        continue; // Requisito: O servidor deve descartar a mensagem
                    }
                    System.out.println("[Handler] HMAC verificado com sucesso.");

                    // decifrar
                    byte[] decryptedData = SecurityUtils.decrypt(this.sharedKey, encryptedData);
                    String command = new String(decryptedData, StandardCharsets.UTF_8);
                    System.out.println("[Handler] Comando decifrado: " + command);

                    // processar o comando
                    String response = processCommand(command);

                    // enviar resposta segura
                    sendSecureMessage(response);

                } catch (Exception e) {
                    System.err.println("[Handler] Erro ao processar mensagem: " + e.getMessage());
                }
            }
        } catch (Exception e) {
        } finally {
            if (outputWriter != null) {
                subscribers.remove(outputWriter);
                System.out.println("[Handler] Cliente desconectado.");
            }
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }

    private String processCommand(String command) {
        String[] parts = command.split(" ");
        String operation = parts[0].toUpperCase();

        switch (operation) {
            case "REGISTER_QUERY": // cliente requisitante se registra
                if (!subscribers.contains(this.outputWriter)) {
                    subscribers.add(this.outputWriter);
                    System.out.println("[Handler] Cliente requisitante registrado para atualizações.");
                }
                return "OK;Registrado para atualizações.";

            case "RESOLVE": // cliente requisitante consulta
                if (parts.length < 2) return "ERROR;Formato inválido. Use: RESOLVE <nome>";
                String name = parts[1];
                String ip = dnsMap.get(name);
                return (ip != null) ? "OK;" + name + " -> " + ip : "ERROR;Nome não encontrado: " + name;

            case "UPDATE": // cliente registrador atualiza
                if (parts.length < 3) return "ERROR;Formato inválido. Use: UPDATE <nome> <novo_ip>";
                String nameToUpdate = parts[1];
                String newIp = parts[2];

                if (!nameToUpdate.equals("servidor1") &&
                        !nameToUpdate.equals("servidor4") &&
                        !nameToUpdate.equals("servidor9")) {
                    return "ERROR;Permissão negada para atualizar " + nameToUpdate;
                }

                dnsMap.put(nameToUpdate, newIp);
                System.out.println("[Handler] BINDING DINÂMICO: " + nameToUpdate + " atualizado para " + newIp);
                notifySubscribers(nameToUpdate, newIp);
                return "OK;Atualizado com sucesso: " + nameToUpdate + " -> " + newIp;

            default:
                return "ERROR;Comando desconhecido: " + operation;
        }
    }

    private void sendSecureMessage(String plainMessage) throws Exception {
        System.out.println("[Handler] Enviando resposta (plana): " + plainMessage);
        byte[] data = plainMessage.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedData = SecurityUtils.encrypt(this.sharedKey, data);
        byte[] hmac = SecurityUtils.calculateHmac(this.sharedKey, encryptedData);
        String hmacHex = ConverterUtils.bytes2Hex(hmac);
        String encryptedHex = ConverterUtils.bytes2Hex(encryptedData);
        this.outputWriter.println(hmacHex + "::" + encryptedHex);
    }

    private void notifySubscribers(String name, String newIp) {
        String message = "UPDATED;" + name + ";" + newIp;
        System.out.println("[Handler] Notificando " + subscribers.size() + " clientes...");

        synchronized (subscribers) {
            for (PrintWriter writer : subscribers) {
                try {
                    byte[] data = message.getBytes(StandardCharsets.UTF_8);
                    byte[] encryptedData = SecurityUtils.encrypt(this.sharedKey, data);
                    byte[] hmac = SecurityUtils.calculateHmac(this.sharedKey, encryptedData);
                    writer.println(ConverterUtils.bytes2Hex(hmac) + "::" + ConverterUtils.bytes2Hex(encryptedData));
                } catch (Exception e) {
                    System.err.println("[Handler] Erro ao notificar cliente: " + e.getMessage());
                }
            }
        }
    }
}