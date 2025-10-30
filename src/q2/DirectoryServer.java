package q2;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class DirectoryServer {

    private static final int PORT = 12346;
    private final Map<String, List<String>> serviceMap = new ConcurrentHashMap<>();
    private final Map<String, Integer> roundRobinMap = new ConcurrentHashMap<>();

    // Chave secreta COMPARTILHADA
    public static final byte[] SHARED_SECRET_KEY =
            "chave-secreta-super-segura".getBytes(StandardCharsets.UTF_8);

    public void start() {
        System.out.println("[DirServer] Servidor de Diretório (Seguro) iniciado na porta " + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[DirServer] Novo cliente conectado: " + clientSocket.getInetAddress());

                // cria uma nova thread para lidar com o cliente
                DirectoryHandler handler = new DirectoryHandler(
                        clientSocket,
                        serviceMap,
                        roundRobinMap,
                        SHARED_SECRET_KEY
                );
                Thread clientThread = new Thread(handler);
                clientThread.start();
            }
        } catch (Exception e) {
            System.err.println("[DirServer] Erro ao iniciar: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        new DirectoryServer().start();
    }
}