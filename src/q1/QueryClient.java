package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Cliente Requisitante (Questão 1).
 * - Envia comandos de consulta (RESOLVE).
 * - Ouve atualizações (binding dinâmico) numa thread separada.
 */
public class QueryClient {

    private static final String HOST = "localhost";
    private static final int PORTA = 12345;

    // Chave secreta COMPARTILHADA (para HMAC e Cifra)
    // private static final byte[] CHAVE_SECRETA = MiniDNSServer.CHAVE_SECRETA;

    // Para testar a falha (descomente a linha abaixo e comente a de cima)
    private static final byte[] CHAVE_SECRETA =
        "chave-errada".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {

        try (
                Socket socket = new Socket(HOST, PORTA);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))
        ) {
            System.out.println("[Cliente Requisitante] Conectado ao servidor.");

            // 1. Inicia a thread para ouvir atualizações do servidor
            Thread listenerThread = new Thread(new ServerListener(in, CHAVE_SECRETA));
            listenerThread.start();

            // 2. Registra-se no servidor para receber atualizações
            enviarMensagemSegura(out, "REGISTER_QUERY", CHAVE_SECRETA);

            // 3. Loop principal para enviar comandos (entrada do usuário)
            System.out.println("Comandos disponíveis: RESOLVE <nome> | SAIR");
            System.out.print("> ");

            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) {
                    break;
                }

                enviarMensagemSegura(out, userInput, CHAVE_SECRETA);
                System.out.print("> ");
            }

            listenerThread.interrupt();
            System.out.println("[Cliente Requisitante] Desconectado.");

        } catch (Exception e) {
            System.err.println("[Cliente Requisitante] Erro: " + e.getMessage());
        }
    }

    /**
     * Prepara e envia uma mensagem segura (Cifrada + HMAC) para o servidor.
     */
    public static void enviarMensagemSegura(PrintWriter out, String mensagemPlana, byte[] chave) throws Exception {
        byte[] dadosCifrados = SecurityUtils.cifrar(chave,
                mensagemPlana.getBytes(StandardCharsets.UTF_8));
        byte[] hmac = SecurityUtils.calcularHmac(chave, dadosCifrados);

        String hmacHex = ConverterUtils.bytes2Hex(hmac);
        String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);

        String mensagemSegura = hmacHex + "::" + cifraHex;
        out.println(mensagemSegura);
    }

    /**
     * Thread interna para escutar passivamente as mensagens do servidor.
     */
    static class ServerListener implements Runnable {

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
}

