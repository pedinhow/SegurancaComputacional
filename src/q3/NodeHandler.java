package q3;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Thread para lidar com uma conexão *recebida* de outro nó.
 * Age como a parte "Servidor".
 */
class NodeHandler implements Runnable {

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
            String linhaRecebida = in.readLine();
            if (linhaRecebida == null) return;

            node.log("Mensagem recebida (bruta): " + linhaRecebida);

            // 1. Decodificar
            String[] partes = linhaRecebida.split("::");
            if (partes.length != 2) {
                node.log("ERRO: Formato de segurança inválido. Descartando.");
                return;
            }

            byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
            byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

            // 2. Verificar HMAC (Teste de Falha)
            //    [cite: 742, 743, 744, 745]
            boolean hmacValido = SecurityUtils.checarHmac(RingNode.CHAVE_SECRETA, dadosCifrados, hmacRecebido);
            if (!hmacValido) {
                node.log("FALHA DE SEGURANÇA: HMAC inválido (chave errada?). Mensagem descartada.");
                // Requisito: Descartar a mensagem [cite: 743, 745]
                return;
            }

            node.log("HMAC verificado com sucesso.");

            // 3. Decifrar
            byte[] dadosDecifrados = SecurityUtils.decifrar(RingNode.CHAVE_SECRETA, dadosCifrados);
            String payload = new String(dadosDecifrados, StandardCharsets.UTF_8);

            node.log("Mensagem decifrada: " + payload);

            // 4. Processar (Verificar se é meu ou encaminhar)
            node.processarMensagem(payload);

        } catch (Exception e) {
            node.log("ERRO no Handler: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }
}
