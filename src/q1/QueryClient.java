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
    private static final byte[] CHAVE_SECRETA = DnsServer.CHAVE_SECRETA;

    // Para testar a falha (descomente a linha abaixo e comente a de cima)
    // private static final byte[] CHAVE_SECRETA =
    //    "chave-errada".getBytes(StandardCharsets.UTF_8);

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
}

