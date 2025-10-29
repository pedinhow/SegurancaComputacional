package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Cliente de Calculadora (Questão 2).
 * - Pede ao usuário uma operação (ex: SOMA 10 5).
 * - Conecta-se ao DirectoryServer para DESCOBRIR o serviço[cite: 743, 744].
 * - Conecta-se ao CalculatorServer (retornado pelo diretório) para executar a operação.
 */
public class CalculatorClient {

    private static final String DIR_HOST = "localhost";
    private static final int DIR_PORTA = 12346;

    // Chave secreta COMPARTILHADA
    // private static final byte[] CHAVE_SECRETA = DirectoryServer.CHAVE_SECRETA;

    // Para testar a falha de segurança[cite: 756]:
    private static final byte[] CHAVE_SECRETA =
        "chave-errada".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) {

        try (BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println("[Cliente Calc] Conectado.");
            System.out.println("Use o formato: <OPERACAO> <n1> <n2> (ex: SOMA 10 20)");
            System.out.println("Operações: SOMA, SUBTRACAO, MULTIPLICACAO, DIVISAO");
            System.out.println("Digite SAIR para fechar.");
            System.out.print("> ");

            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) break;

                String[] partesComando = userInput.split(" ");
                if (partesComando.length < 1) {
                    System.out.print("> ");
                    continue;
                }

                String servico = partesComando[0].toUpperCase();

                try {
                    // 1. Descobrir o serviço
                    String enderecoServidor = descobrirServico(servico);
                    if (enderecoServidor == null) {
                        System.err.println("Não foi possível descobrir o serviço: " + servico);
                        System.out.print("> ");
                        continue;
                    }

                    System.out.println("Serviço '" + servico + "' encontrado em: " + enderecoServidor + " (via Round Robin)");

                    // 2. Executar o cálculo
                    String resultado = executarCalculo(enderecoServidor, userInput);
                    System.out.println("Resultado: " + resultado);

                } catch (Exception e) {
                    System.err.println("Erro durante a operação: " + e.getMessage());
                }

                System.out.print("> ");
            }

            System.out.println("[Cliente Calc] Desconectado.");

        } catch (Exception e) {
            System.err.println("[Cliente Calc] Erro: " + e.getMessage());
        }
    }

    /**
     * Conecta-se ao DirectoryServer para descobrir o endereço de um serviço.
     */
    private static String descobrirServico(String servico) throws Exception {
        try (
                Socket socket = new Socket(DIR_HOST, DIR_PORTA);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            String comando = "DISCOVER " + servico;

            // Envia comando seguro
            enviarMensagemSegura(out, comando, CHAVE_SECRETA);

            // Ouve a resposta
            String resposta = in.readLine();
            if (resposta == null) throw new RuntimeException("Servidor de diretório não respondeu.");

            String respostaPlana = processarResposta(resposta, CHAVE_SECRETA, "DirServer");

            if (respostaPlana.startsWith("OK;")) {
                return respostaPlana.substring(3); // Retorna o endereço (ex: "localhost:9001")
            } else {
                throw new RuntimeException(respostaPlana); // Ex: "ERROR;Serviço não encontrado"
            }
        }
    }

    /**
     * Conecta-se ao CalculatorServer (no endereço descoberto) e executa o cálculo.
     */
    private static String executarCalculo(String endereco, String comando) throws Exception {
        String[] partesEndereco = endereco.split(":");
        String host = partesEndereco[0];
        int porta = Integer.parseInt(partesEndereco[1]);

        try (
                Socket socket = new Socket(host, porta);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            // Envia comando seguro
            enviarMensagemSegura(out, comando, CHAVE_SECRETA);

            // Ouve a resposta
            String resposta = in.readLine();
            if (resposta == null) throw new RuntimeException("Servidor de cálculo não respondeu.");

            String respostaPlana = processarResposta(resposta, CHAVE_SECRETA, "CalcServer");

            if (respostaPlana.startsWith("OK;")) {
                return respostaPlana.substring(3); // Retorna o resultado
            } else {
                return respostaPlana; // Retorna a mensagem de erro
            }
        }
    }

    // --- Métodos utilitários de segurança ---

    private static void enviarMensagemSegura(PrintWriter out, String mensagemPlana, byte[] chave) throws Exception {
        byte[] dadosCifrados = SecurityUtils.cifrar(chave,
                mensagemPlana.getBytes(StandardCharsets.UTF_8));
        byte[] hmac = SecurityUtils.calcularHmac(chave, dadosCifrados);
        String hmacHex = ConverterUtils.bytes2Hex(hmac);
        String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);
        out.println(hmacHex + "::" + cifraHex);
    }

    private static String processarResposta(String linhaRecebida, byte[] chave, String nomeServidor) throws Exception {
        try {
            String[] partes = linhaRecebida.split("::");
            if (partes.length != 2) throw new SecurityException("Formato de resposta inválido.");

            byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
            byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

            boolean hmacValido = SecurityUtils.checarHmac(chave, dadosCifrados, hmacRecebido);
            if (!hmacValido) throw new SecurityException("HMAC da resposta inválido (chave errada?).");

            byte[] dadosDecifrados = SecurityUtils.decifrar(chave, dadosCifrados);
            return new String(dadosDecifrados, StandardCharsets.UTF_8);

        } catch (Exception e) {
            System.err.println("[" + nomeServidor + " Resposta] Erro ao processar resposta: " + e.getMessage());
            throw e;
        }
    }
}