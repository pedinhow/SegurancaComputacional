package q3;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class NodeHandler implements Runnable {

    private final Socket socket;
    private final RingNode node; // Referência de volta ao nó principal

    public NodeHandler(Socket socket, RingNode node) {
        this.socket = socket;
        this.node = node;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            String receivedLine = in.readLine();
            if (receivedLine == null) return;

            node.log("Mensagem recebida (bruta): " + receivedLine);

            // 1. Decodificar
            String[] parts = receivedLine.split("::");
            if (parts.length != 2) {
                node.log("ERRO: Formato de segurança inválido. Descartando.");
                return;
            }
            byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
            byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

            // 2. Verificar HMAC [cite: 288, 290]
            boolean isHmacValid = SecurityUtils.checkHmac(RingNode.SHARED_SECRET_KEY, encryptedData, receivedHmac);
            if (!isHmacValid) {
                node.log("FALHA DE SEGURANÇA: HMAC inválido (chave errada?). Mensagem descartada.");
                return; // Requisito: Descartar a mensagem [cite: 291, 293]
            }
            node.log("HMAC verificado com sucesso.");

            // 3. Decifrar [cite: 287]
            byte[] decryptedData = SecurityUtils.decrypt(RingNode.SHARED_SECRET_KEY, encryptedData);
            String payload = new String(decryptedData, StandardCharsets.UTF_8);
            node.log("Mensagem decifrada: " + payload);

            // 4. Processar
            String[] payloadParts = payload.split(";");
            if (payloadParts[0].equals("SEARCH")) {
                node.processMessage(payload); // Deixa o nó principal processar
            } else if (payloadParts[0].equals("FOUND")) {
                handleFound(payloadParts);
            }

        } catch (Exception e) {
            node.log("ERRO no Handler: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }

    private void handleFound(String[] parts) {
        // Formato: "FOUND;ARQUIVO;ID_ONDE_ACHOU"
        if (parts.length < 3) return;
        String file = parts[1];
        String foundAtNodeId = parts[2];

        node.log("!!! SUCESSO DA BUSCA !!!");
        node.log("O arquivo '" + file + "' foi localizado no Nó " + foundAtNodeId + ".");
    }
}