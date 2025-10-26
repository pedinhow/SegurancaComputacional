package q2;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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

