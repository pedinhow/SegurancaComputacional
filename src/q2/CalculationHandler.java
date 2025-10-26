package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Handler para o servidor de calculadora.
 */
class CalculationHandler implements Runnable {

    private final Socket socket;

    public CalculationHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String linhaRecebida = in.readLine();
            if (linhaRecebida == null) return;

            System.out.println("[CalcHandler] Mensagem de cálculo recebida (bruta): " + linhaRecebida);

            try {
                // 1. Decodificar e Verificar Segurança
                String[] partes = linhaRecebida.split("::");
                if (partes.length != 2) throw new SecurityException("Formato inválido.");

                byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
                byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

                boolean hmacValido = SecurityUtils.checarHmac(DirectoryServer.CHAVE_SECRETA, dadosCifrados, hmacRecebido);
                if (!hmacValido) throw new SecurityException("HMAC inválido.");

                System.out.println("[CalcHandler] HMAC verificado.");

                // 2. Decifrar
                byte[] dadosDecifrados = SecurityUtils.decifrar(DirectoryServer.CHAVE_SECRETA, dadosCifrados);
                String comando = new String(dadosDecifrados, StandardCharsets.UTF_8);
                System.out.println("[CalcHandler] Comando decifrado: " + comando);

                // 3. Processar o cálculo
                String resposta = calcular(comando);

                // 4. Enviar resposta segura
                enviarMensagemSegura(out, resposta, DirectoryServer.CHAVE_SECRETA);

            } catch (Exception e) {
                System.err.println("[CalcHandler] Erro de segurança ou cálculo: " + e.getMessage());
                // Não enviar resposta em caso de falha de segurança
            }

        } catch (Exception e) {
            // Silencioso
        } finally {
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }

    /**
     * Realiza a operação de cálculo.
     */
    private String calcular(String comando) {
        String[] partes = comando.split(" ");
        if (partes.length < 3) return "ERROR;Formato inválido. Use: <OPERACAO> <n1> <n2>";

        try {
            String operacao = partes[0].toUpperCase();
            double n1 = Double.parseDouble(partes[1]);
            double n2 = Double.parseDouble(partes[2]);
            double resultado = 0;

            switch (operacao) {
                case "SOMA":
                    resultado = n1 + n2;
                    break;
                case "SUBTRACAO":
                    resultado = n1 - n2;
                    break;
                case "MULTIPLICACAO":
                    resultado = n1 * n2;
                    break;
                case "DIVISAO":
                    if (n2 == 0) return "ERROR;Divisão por zero.";
                    resultado = n1 / n2;
                    break;
                default:
                    return "ERROR;Operação desconhecida: " + operacao;
            }
            return "OK;Resultado: " + resultado;
        } catch (NumberFormatException e) {
            return "ERROR;Números inválidos.";
        }
    }

    /**
     * Envia uma mensagem segura (cifrada + HMAC) para o cliente.
     */
    private void enviarMensagemSegura(PrintWriter out, String mensagemPlana, byte[] chave) throws Exception {
        byte[] dadosCifrados = SecurityUtils.cifrar(chave,
                mensagemPlana.getBytes(StandardCharsets.UTF_8));
        byte[] hmac = SecurityUtils.calcularHmac(chave, dadosCifrados);
        String hmacHex = ConverterUtils.bytes2Hex(hmac);
        String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);
        out.println(hmacHex + "::" + cifraHex);
    }
}
