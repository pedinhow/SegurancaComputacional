package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Servidor de Calculadora (Questão 2).
 * - Oferece serviços de cálculo (SOMA, SUBTRACAO, etc.)[cite: 738, 739].
 * - Ao iniciar, registra seus serviços no DirectoryServer[cite: 741].
 * - Aguarda conexões de clientes para realizar os cálculos.
 */
public class CalculatorServer {

    private static final String DIR_HOST = "localhost";
    private static final int DIR_PORTA = 12346;
    private final int minhaPorta;
    private final String meuEndereco;

    public CalculatorServer(int minhaPorta) {
        this.minhaPorta = minhaPorta;
        this.meuEndereco = "localhost:" + minhaPorta;
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Uso: java q2.CalculatorServer <porta>");
            System.exit(1);
        }

        try {
            int porta = Integer.parseInt(args[0]);
            CalculatorServer calcServer = new CalculatorServer(porta);

            // 1. Registra-se no Servidor de Diretório
            calcServer.registrarServicos();

            // 2. Inicia o próprio serviço de calculadora
            calcServer.iniciarServicoCalculo();

        } catch (NumberFormatException e) {
            System.err.println("Porta inválida: " + args[0]);
        }
    }

    /**
     * Conecta-se ao DirectoryServer e registra os serviços que este servidor oferece.
     */
    private void registrarServicos() {
        // Serviços que este servidor oferece [cite: 738]
        String[] servicos = {"SOMA", "SUBTRACAO", "MULTIPLICACAO", "DIVISAO"};

        System.out.println("[CalcServer-" + minhaPorta + "] Registrando serviços no Diretório...");

        for (String servico : servicos) {
            try (
                    Socket socket = new Socket(DIR_HOST, DIR_PORTA);
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
            ) {
                String comando = "REGISTER " + servico + " " + meuEndereco;

                // Envia comando seguro
                enviarMensagemSegura(out, comando, DirectoryServer.CHAVE_SECRETA);

                // Ouve a resposta (opcional, mas bom para log)
                String resposta = in.readLine();
                if (resposta != null) {
                    processarResposta(resposta, DirectoryServer.CHAVE_SECRETA, "DirServer");
                }

            } catch (Exception e) {
                System.err.println("[CalcServer-" + minhaPorta + "] Erro ao registrar " + servico + ": " + e.getMessage());
            }
        }
        System.out.println("[CalcServer-" + minhaPorta + "] Registro concluído.");
    }

    /**
     * Inicia o ServerSocket para atender clientes de cálculo.
     */
    private void iniciarServicoCalculo() {
        System.out.println("[CalcServer-" + minhaPorta + "] Aguardando clientes de cálculo na porta " + minhaPorta);
        try (ServerSocket serverSocket = new ServerSocket(minhaPorta)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[CalcServer-" + minhaPorta + "] Cliente de cálculo conectado: " + clientSocket.getInetAddress());

                // Cria uma nova thread para o cálculo
                Thread clientThread = new Thread(
                        new CalculationHandler(clientSocket)
                );
                clientThread.start();
            }
        } catch (Exception e) {
            System.err.println("[CalcServer-" + minhaPorta + "] Erro no serviço de cálculo: " + e.getMessage());
        }
    }

    // Métodos utilitários (enviarMensagemSegura, processarResposta)
    // (Similares aos dos outros clientes)

    private void enviarMensagemSegura(PrintWriter out, String mensagemPlana, byte[] chave) throws Exception {
        byte[] dadosCifrados = SecurityUtils.cifrar(chave,
                mensagemPlana.getBytes(StandardCharsets.UTF_8));
        byte[] hmac = SecurityUtils.calcularHmac(chave, dadosCifrados);
        String hmacHex = ConverterUtils.bytes2Hex(hmac);
        String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);
        out.println(hmacHex + "::" + cifraHex);
    }

    private void processarResposta(String linhaRecebida, byte[] chave, String nomeServidor) {
        try {
            String[] partes = linhaRecebida.split("::");
            if (partes.length != 2) return;
            byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
            byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);
            boolean hmacValido = SecurityUtils.checarHmac(chave, dadosCifrados, hmacRecebido);
            if (!hmacValido) return;
            byte[] dadosDecifrados = SecurityUtils.decifrar(chave, dadosCifrados);
            String mensagem = new String(dadosDecifrados, StandardCharsets.UTF_8);
            System.out.println("[" + nomeServidor + " Resposta] " + mensagem);
        } catch (Exception e) { /* ignora */ }
    }
}

