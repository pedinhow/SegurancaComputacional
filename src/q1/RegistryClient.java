package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Cliente Registrador (Questão 1).
 * - Envia comandos de atualização (UPDATE).
 * - Ouve a resposta na mesma thread.
 */
public class RegistryClient {

    private static final String HOST = "localhost";
    private static final int PORTA = 12345;

    // Chave secreta COMPARTILHADA (para HMAC e Cifra)
    private static final byte[] CHAVE_SECRETA = DnsServer.CHAVE_SECRETA;

    // Para testar a falha (descomente a linha abaixo e comente a de cima)
    // private static final byte[] CHAVE_SECRETA =
    //    "chave-do-atacante".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {

        try (
                Socket socket = new Socket(HOST, PORTA);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))
        ) {
            System.out.println("[Cliente Registrador] Conectado ao servidor.");
            System.out.println("Comandos disponíveis: UPDATE <nome> <ip> | SAIR");
            System.out.println("  (Nomes permitidos: servidor1, servidor4, servidor9)");
            System.out.print("> ");

            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) {
                    break;
                }

                // 1. Envia o comando seguro
                enviarMensagemSegura(out, userInput, CHAVE_SECRETA);

                // 2. Ouve a resposta do servidor (na mesma thread)
                String linhaRecebida = in.readLine();
                if (linhaRecebida != null) {
                    processarResposta(linhaRecebida, CHAVE_SECRETA);
                }

                System.out.print("> ");
            }

            System.out.println("[Cliente Registrador] Desconectado.");

        } catch (Exception e) {
            System.err.println("[Cliente Registrador] Erro: " + e.getMessage());
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
     * Processa a resposta recebida do servidor.
     */
    private static void processarResposta(String linhaRecebida, byte[] chave) {
        try {
            String[] partes = linhaRecebida.split("::");
            if (partes.length != 2) {
                System.err.println("[Servidor Resposta] ERRO: Formato inválido.");
                return;
            }

            byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
            byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

            // 1. Verificar HMAC
            boolean hmacValido = SecurityUtils.checarHmac(chave, dadosCifrados, hmacRecebido);

            if (!hmacValido) {
                System.err.println("[Servidor Resposta] FALHA DE SEGURANÇA: HMAC inválido.");
                return;
            }

            // 2. Decifrar
            byte[] dadosDecifrados = SecurityUtils.decifrar(chave, dadosCifrados);
            String mensagem = new String(dadosDecifrados, StandardCharsets.UTF_8);

            // 3. Exibir a mensagem
            System.out.println("[Servidor Resposta] " + mensagem);

        } catch (Exception e) {
            System.err.println("[Servidor Resposta] Erro ao processar mensagem: " + e.getMessage());
        }
    }
}
