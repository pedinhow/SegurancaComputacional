package q1;

import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MiniDNSServer {

    private static final int PORT = 12345;
    private final Map<String, String> dnsMap = new ConcurrentHashMap<>();
    private final List<PrintWriter> subscribers =
            java.util.Collections.synchronizedList(new ArrayList<>());

    // Chave secreta COMPARTILHADA
    public static final byte[] SHARED_SECRET_KEY =
            "chave-secreta-super-segura".getBytes(StandardCharsets.UTF_8);

    public MiniDNSServer() {
        initializeDnsMap();
    }

    private void initializeDnsMap() {
        // Popula o mapa inicial [cite: 230-231]
        dnsMap.put("servidor1", "192.168.0.10");
        dnsMap.put("servidor2", "192.168.0.20");
        dnsMap.put("servidor3", "192.168.0.30");
        dnsMap.put("servidor4", "192.168.0.40");
        dnsMap.put("servidor5", "192.168.0.50");
        dnsMap.put("servidor6", "192.168.0.60");
        dnsMap.put("servidor7", "192.168.0.70");
        dnsMap.put("servidor8", "192.168.0.80");
        dnsMap.put("servidor9", "192.168.0.90");
        dnsMap.put("servidor10", "192.168.0.100");
    }

    public void start() {
        System.out.println("[Servidor] Mini-DNS (Seguro) iniciado na porta " + PORT);
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[Servidor] Novo cliente conectado: " + clientSocket.getInetAddress());

                // Cria uma nova thread para lidar com o cliente
                ClientHandler handler = new ClientHandler(
                        clientSocket,
                        dnsMap,
                        subscribers,
                        SHARED_SECRET_KEY
                );
                Thread clientThread = new Thread(handler);
                clientThread.start();
            }
        } catch (Exception e) {
            System.err.println("[Servidor] Erro ao iniciar: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        new MiniDNSServer().start();
    }
}