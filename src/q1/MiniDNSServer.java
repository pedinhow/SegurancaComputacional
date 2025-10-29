package q1;

import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Servidor Mini-DNS (Questão 1).
 * Implementação completa com segurança (HMAC + Cifra) e binding dinâmico.
 */
public class MiniDNSServer {

    private static final int PORTA = 12345;

    // Usamos ConcurrentHashMap para segurança em ambiente multithread.
    private final Map<String, String> mapaDns = new ConcurrentHashMap<>();

    // Lista para notificar clientes (requisito de binding dinâmico)
    private final List<PrintWriter> clientesRequisitantes =
            java.util.Collections.synchronizedList(new ArrayList<>());

    // Chave secreta COMPARTILHADA (para HMAC e Cifra)
    public static final byte[] CHAVE_SECRETA =
            "chave-secreta-super-segura".getBytes(StandardCharsets.UTF_8);

    public MiniDNSServer() {
        // Popula o mapa inicial
        mapaDns.put("servidor1", "192.168.0.10");
        mapaDns.put("servidor2", "192.168.0.20");
        mapaDns.put("servidor3", "192.168.0.30");
        mapaDns.put("servidor4", "192.168.0.40");
        mapaDns.put("servidor5", "192.168.0.50");
        mapaDns.put("servidor6", "192.168.0.60");
        mapaDns.put("servidor7", "192.168.0.70");
        mapaDns.put("servidor8", "192.168.0.80");
        mapaDns.put("servidor9", "192.168.0.90");
        mapaDns.put("servidor10", "192.168.0.100");
    }

    public void iniciar() {
        System.out.println("[Servidor] Mini-DNS iniciado na porta " + PORTA);
        try (ServerSocket serverSocket = new ServerSocket(PORTA)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[Servidor] Novo cliente conectado: " + clientSocket.getInetAddress());

                // Cria uma nova thread para lidar com o cliente
                Thread clientThread = new Thread(
                        new ClientHandler(clientSocket, mapaDns, clientesRequisitantes)
                );
                clientThread.start();
            }
        } catch (Exception e) {
            System.err.println("[Servidor] Erro ao iniciar: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        MiniDNSServer server = new MiniDNSServer();
        server.iniciar();
    }
}

