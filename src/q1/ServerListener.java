package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;

/**
 * Thread interna para escutar passivamente as mensagens do servidor.
 */
class ServerListener implements Runnable {

    private final BufferedReader in;
    private final byte[] chaveSecreta;

    public ServerListener(BufferedReader in, byte[] chave) {
        this.in = in;
        this.chaveSecreta = chave;
    }

    @Override
    public void run() {
        try {
            String linhaRecebida;
            while (Thread.currentThread().isInterrupted() == false && (linhaRecebida = in.readLine()) != null) {

                try {
                    String[] partes = linhaRecebida.split("::");
                    if (partes.length != 2) {
                        System.err.println("\n[Servidor Resposta] ERRO: Formato inválido.");
                        continue;
                    }

                    byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
                    byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

                    // 1. Verificar HMAC
                    boolean hmacValido = SecurityUtils.checarHmac(chaveSecreta, dadosCifrados, hmacRecebido);

                    if (!hmacValido) {
                        System.err.println("\n[Servidor Resposta] FALHA DE SEGURANÇA: HMAC inválido. Mensagem descartada.");
                        continue;
                    }

                    // 2. Decifrar
                    byte[] dadosDecifrados = SecurityUtils.decifrar(chaveSecreta, dadosCifrados);
                    String mensagem = new String(dadosDecifrados, StandardCharsets.UTF_8);

                    // 3. Exibir a mensagem
                    System.out.println("\n[Servidor Resposta] " + mensagem);
                    System.out.print("> ");

                } catch (Exception e) {
                    System.err.println("\n[Servidor Resposta] Erro ao processar mensagem: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            // Socket fechado
        }
    }
}
