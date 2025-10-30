package q3;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class NodeHandler implements Runnable {

    private final Socket socket;
    private final P2PNode node;

    public NodeHandler(Socket socket, P2PNode node) {
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

            String[] parts = receivedLine.split("::");
            if (parts.length != 2) {
                node.log("ERRO: Formato de segurança inválido. Descartando.");
                return;
            }
            byte[] receivedHmac = ConverterUtils.hex2Bytes(parts[0]);
            byte[] encryptedData = ConverterUtils.hex2Bytes(parts[1]);

            boolean isHmacValid = SecurityUtils.checkHmac(P2PNode.SHARED_SECRET_KEY, encryptedData, receivedHmac);
            if (!isHmacValid) {
                node.log("FALHA DE SEGURANÇA: HMAC inválido (chave errada?). Mensagem descartada.");
                return;
            }
            node.log("HMAC verificado com sucesso.");

            byte[] decryptedData = SecurityUtils.decrypt(P2PNode.SHARED_SECRET_KEY, encryptedData);
            String payload = new String(decryptedData, StandardCharsets.UTF_8);
            node.log("Mensagem decifrada: " + payload);

            node.processMessage(payload);

        } catch (Exception e) {
            node.log("ERRO no Handler: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (Exception e) {

            }
        }
    }
}