package q2;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Servidor de Diretório (Questão 2).
 * - Registra serviços (CalculatorServers).
 * - Permite que clientes descubram serviços (CalculatorClient).
 * - Implementa Load Balancing Round Robin.
 * - Implementa segurança (Cifra + HMAC) .
 */
public class DirectoryServer {

    private static final int PORTA = 12346; // Porta diferente da Q1

    // Mapeia um nome de serviço (ex: "SOMA") para uma lista de endereços (ex: ["host:9001", "host:9002"])
    private final Map<String, List<String>> mapaServicos = new ConcurrentHashMap<>();

    // Mapeia um serviço para o próximo índice a ser usado no Round Robin
    private final Map<String, Integer> indicesRoundRobin = new ConcurrentHashMap<>();

    // Chave secreta COMPARTILHADA
    public static final byte[] CHAVE_SECRETA =
            "chave-secreta-super-segura".getBytes(StandardCharsets.UTF_8);

    public void iniciar() {
        System.out.println("[DirServer] Servidor de Diretório iniciado na porta " + PORTA);
        try (ServerSocket serverSocket = new ServerSocket(PORTA)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[DirServer] Novo cliente conectado: " + clientSocket.getInetAddress());

                // Cria uma nova thread para lidar com o cliente
                Thread clientThread = new Thread(
                        new DirectoryClientHandler(clientSocket, mapaServicos, indicesRoundRobin)
                );
                clientThread.start();
            }
        } catch (Exception e) {
            System.err.println("[DirServer] Erro ao iniciar: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        DirectoryServer server = new DirectoryServer();
        server.iniciar();
    }
}

/**
 * Handler para clientes do Servidor de Diretório.
 */
class DirectoryClientHandler implements Runnable {

    private final Socket socket;
    private final Map<String, List<String>> mapaServicos;
    private final Map<String, Integer> indicesRoundRobin;

    public DirectoryClientHandler(Socket socket, Map<String, List<String>> mapaServicos, Map<String, Integer> indicesRoundRobin) {
        this.socket = socket;
        this.mapaServicos = mapaServicos;
        this.indicesRoundRobin = indicesRoundRobin;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String linhaRecebida;

            while ((linhaRecebida = in.readLine()) != null) {
                System.out.println("\n[DirHandler] Mensagem recebida (bruta): " + linhaRecebida);

                try {
                    // 1. Decodificar e Verificar Segurança
                    String[] partes = linhaRecebida.split("::");
                    if (partes.length != 2) {
                        System.err.println("[DirHandler] ERRO: Formato inválido. Descartando.");
                        continue;
                    }

                    byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
                    byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

                    // 2. Verificar HMAC (Teste de Falha)
                    //    Se a chave estiver errada, falha e descarta [cite: 756, 757]
                    boolean hmacValido = SecurityUtils.checarHmac(DirectoryServer.CHAVE_SECRETA, dadosCifrados, hmacRecebido);

                    if (!hmacValido) {
                        System.err.println("[DirHandler] FALHA DE SEGURANÇA: HMAC inválido. Mensagem descartada.");
                        continue;
                    }

                    System.out.println("[DirHandler] HMAC verificado com sucesso.");

                    // 3. Decifrar
                    byte[] dadosDecifrados = SecurityUtils.decifrar(DirectoryServer.CHAVE_SECRETA, dadosCifrados);
                    String comando = new String(dadosDecifrados, StandardCharsets.UTF_8);
                    System.out.println("[DirHandler] Comando decifrado: " + comando);

                    // 4. Processar o comando
                    String resposta = processarComando(comando);

                    // 5. Enviar resposta segura
                    enviarMensagemSegura(out, resposta, DirectoryServer.CHAVE_SECRETA);

                } catch (Exception e) {
                    System.err.println("[DirHandler] Erro ao processar mensagem: " + e.getMessage());
                    // Não enviar resposta em caso de falha de segurança
                }

                // Em geral, clientes do diretório conectam, fazem uma ação e desconectam.
                // Mas mantemos o loop caso um cliente queira fazer várias ações.
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
     * Processa o comando (REGISTER ou DISCOVER).
     */
    private String processarComando(String comando) {
        String[] partes = comando.split(" ");
        String operacao = partes[0].toUpperCase();

        switch (operacao) {
            case "REGISTER": // Enviado por um CalculatorServer
                // Formato: REGISTER <servico> <host:porta>
                if (partes.length < 3) return "ERROR;Formato inválido. Use: REGISTER <servico> <host:porta>";

                String servico = partes[1].toUpperCase();
                String endereco = partes[2];

                // Adiciona o serviço ao mapa
                // computeIfAbsent garante a criação da lista de forma thread-safe
                mapaServicos.computeIfAbsent(servico, k ->
                        java.util.Collections.synchronizedList(new ArrayList<>())
                ).add(endereco);

                indicesRoundRobin.putIfAbsent(servico, 0); // Inicia o índice do Round Robin

                System.out.println("[DirHandler] Serviço registrado: " + servico + " em " + endereco);
                return "OK;Serviço " + servico + " registrado em " + endereco;

            case "DISCOVER": // Enviado por um CalculatorClient [cite: 743]
                // Formato: DISCOVER <servico>
                if (partes.length < 2) return "ERROR;Formato inválido. Use: DISCOVER <servico>";

                String servicoBusca = partes[1].toUpperCase();
                List<String> servidores = mapaServicos.get(servicoBusca);

                if (servidores == null || servidores.isEmpty()) {
                    return "ERROR;Serviço não encontrado: " + servicoBusca;
                }

                // Lógica de Load Balancing - Round Robin
                int index = indicesRoundRobin.compute(servicoBusca, (k, v) -> (v == null) ? 0 : (v + 1));
                String servidorEscolhido = servidores.get(index % servidores.size());

                System.out.println("[DirHandler] Descoberta: " + servicoBusca + " -> " + servidorEscolhido + " (Round Robin)");
                return "OK;" + servidorEscolhido;

            default:
                return "ERROR;Comando desconhecido: " + operacao;
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

        String mensagemSegura = hmacHex + "::" + cifraHex;
        out.println(mensagemSegura);
    }
}
