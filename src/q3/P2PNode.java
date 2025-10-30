package q3;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

public class P2PNode {

    private final String nodeId;   // P0, P1, ...
    private final int port;
    private final String successorHost;
    private final int successorPort;
    private final String predecessorHost;
    private final int predecessorPort;
    private final String myIp;
    private final Set<String> localFiles = new HashSet<>();

    // chave secreta
    public static final byte[] SHARED_SECRET_KEY =
            "chave-secreta-do-anel-p2p".getBytes(StandardCharsets.UTF_8);

    // para testar a falha de segurança TODO descomente
    // public static final byte[] SHARED_SECRET_KEY =
    //    "chave-errada-do-intruso".getBytes(StandardCharsets.UTF_8);

    public P2PNode(String nodeId, int port, String successorHost, int successorPort,
                   String predecessorHost, int predecessorPort, String myIp) {
        this.nodeId = nodeId;
        this.port = port;
        this.successorHost = successorHost;
        this.successorPort = successorPort;
        this.predecessorHost = predecessorHost;
        this.predecessorPort = predecessorPort;
        this.myIp = myIp;
        this.initializeFiles();
    }

    public static void main(String[] args) {
        if (args.length < 7) {
            System.err.println("Uso: java q3.P2PNode <id> <porta> <sucessorHost> <sucessorPort> <antecessorHost> <antecessorPort> <meuIp>");
            System.err.println("Exemplo: java q3.P2PNode P0 9000 172.17.232.64 9001 192.168.1.5 9005 172.17.232.64");
            System.exit(1);
        }

        String id = args[0];
        int port = Integer.parseInt(args[1]);
        String succHost = args[2];
        int succPort = Integer.parseInt(args[3]);
        String predHost = args[4];
        int predPort = Integer.parseInt(args[5]);
        String myIp = args[6];

        P2PNode node = new P2PNode(id, port, succHost, succPort, predHost, predPort, myIp);
        node.start();
    }

    public void start() {
        log("Nó (Seguro) iniciado. IP: " + myIp + ", Porta: " + port + ", Sucessor: " + successorHost + ":" + successorPort + ", Antecessor: " + predecessorHost + ":" + predecessorPort);
        new Thread(this::startServer).start();
        startConsole();
    }

    private void startConsole() {
        Scanner sc = new Scanner(System.in);
        System.out.println("Comandos: SEARCH <arquivoX> HORARIO|ANTIHORARIO | SAIR");
        while (true) {
            System.out.print(nodeId + "> ");
            String input = sc.nextLine();
            if (input.equalsIgnoreCase("SAIR")) break;

            String[] parts = input.split(" ");
            if (parts.length != 3) {
                log("Erro na entrada de dados. Tente outra vez!");
                continue;
            }

            String command = parts[0];
            String file = parts[1];
            String direction = parts[2].toUpperCase();

            if (!command.equalsIgnoreCase("SEARCH") ||
                    (!direction.equals("HORARIO") && !direction.equals("ANTIHORARIO"))) {
                log("Erro na entrada de dados. Tente outra vez!");
                continue;
            }

            String payload = "SEARCH;" + file + ";" + nodeId + ";" + this.myIp + ";" + port + ";" + direction;
            processMessage(payload);
        }
        sc.close();
    }

    private void startServer() {
        try (ServerSocket server = new ServerSocket(port)) {
            while (true) {
                Socket client = server.accept();
                new Thread(new NodeHandler(client, this)).start();
            }
        } catch (IOException e) {
            log("Erro no servidor: " + e.getMessage());
        }
    }

    public void processMessage(String plainPayload) {
        try {
            String[] parts = plainPayload.split(";");
            if (parts.length < 6) {
                log("Mensagem mal formatada (pós-decr.): " + plainPayload);
                return;
            }

            String type = parts[0];
            if (type.equals("SEARCH")) {
                String file = parts[1];
                String originId = parts[2];
                String originHost = parts[3];
                int originPort = Integer.parseInt(parts[4]);
                String direction = parts[5];

                if (isResponsible(file)) {
                    log("ARQUIVO ENCONTRADO! '" + file + "' neste nó (" + nodeId + ")");
                    String response = "FOUND;" + file + ";" + nodeId;
                    sendSecureMessage(originHost, originPort, response);
                } else {
                    log("Arquivo '" + file + "' não está aqui. Encaminhando...");
                    if (direction.equals("HORARIO")) {
                        sendSecureMessage(successorHost, successorPort, plainPayload);
                    } else {
                        sendSecureMessage(predecessorHost, predecessorPort, plainPayload);
                    }
                }
            } else if (type.equals("FOUND")) {
                String file = parts[1];
                String foundAtNode = parts[2];
                log("!!! SUCESSO DA BUSCA !!!");
                log("O arquivo '" + file + "' foi localizado no Nó " + foundAtNode + ".");
            }

        } catch (Exception e) {
            log("Erro processando mensagem: " + e.getMessage());
        }
    }

    public void sendSecureMessage(String host, int port, String plainPayload) {
        log("Enviando (seguro): " + plainPayload + " para " + host + ":" + port);
        try {
            byte[] data = plainPayload.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedData = SecurityUtils.encrypt(SHARED_SECRET_KEY, data);
            byte[] hmac = SecurityUtils.calculateHmac(SHARED_SECRET_KEY, encryptedData);

            String hmacHex = ConverterUtils.bytes2Hex(hmac);
            String encryptedHex = ConverterUtils.bytes2Hex(encryptedData);

            sendRawMessage(host, port, hmacHex + "::" + encryptedHex);

        } catch (Exception e) {
            log("Erro ao criptografar ou enviar mensagem: " + e.getMessage());
        }
    }

    private void sendRawMessage(String host, int port, String rawPayload) {
        try (Socket socket = new Socket(host, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            out.println(rawPayload);
        } catch (Exception e) {
            log("Erro enviando mensagem bruta: " + e.getMessage());
        }
    }

    private boolean isResponsible(String file) {
        try {
            int idNum = Integer.parseInt(nodeId.replace("P", ""));
            int fileNum = Integer.parseInt(file.replaceAll("(?i)arquivo", ""));
            int min = idNum * 10 + 1;
            int max = idNum * 10 + 10;
            return fileNum >= min && fileNum <= max;
        } catch (NumberFormatException e) {
            log("Formato de arquivo ou ID inválido: " + file + " / " + nodeId);
            return false;
        }
    }

    private void initializeFiles() {
        int idNum = Integer.parseInt(nodeId.replace("P",""));
        int min = idNum * 10 + 1;
        int max = idNum * 10 + 10;
        for (int i = min; i <= max; i++) localFiles.add("arquivo" + i);
        log("Arquivos locais (simulados): " + min + " a " + max);
    }

    public void log(String msg) {
        System.out.println("[" + nodeId + " | " + java.time.LocalTime.now() + "] " + msg);
    }
}