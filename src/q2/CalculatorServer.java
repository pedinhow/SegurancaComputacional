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
                case "SOMA": resultado = n1 + n2; break;
                case "SUBTRACAO": resultado = n1 - n2; break;
                case "MULTIPLICACAO": resultado = n1 * n2; break;
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
