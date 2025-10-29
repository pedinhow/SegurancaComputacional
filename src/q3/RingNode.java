package q3;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class RingNode {

    private final String nodeId; // ex: "P0"
    private final int port;
    private final String successorHost = "localhost";
    private final int successorPort;

    // Chave secreta COMPARTILHADA [cite: 286]
    public static final byte[] SHARED_SECRET_KEY =
            "chave-secreta-do-anel-p2p".getBytes(StandardCharsets.UTF_8);

    // Para testar a falha de segurança (Nó P7 ou chave errada) [cite: 290-292]
    // public static final byte[] SHARED_SECRET_KEY =
    //    "chave-errada-do-intruso".getBytes(StandardCharsets.UTF_8);

    public RingNode(String nodeId, int port, int successorPort) {
        this.nodeId = nodeId;
        this.port = port;
        this.successorPort = successorPort;
    }

    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Uso: java q3.RingNode <meu_id> <minha_porta> <porta_sucessor>");
            System.err.println("Exemplo (P0): java q3.RingNode P0 9000 9001");
            System.err.println("Exemplo (P5): java q3.RingNode P5 9005 9000 (fecha o anel)");
            System.exit(1);
        }
        try {
            String id = args[0];
            int port = Integer.parseInt(args[1]);
            int successorPort = Integer.parseInt(args[2]);
            new RingNode(id, port, successorPort).start();
        } catch (Exception e) {
            System.err.println("Erro ao iniciar nó: " + e.getMessage());
        }
    }

    public void start() {
        log("Nó " + nodeId + " (Seguro) iniciado. Ouvindo na porta " + port + ". Sucessor na porta " + successorPort);
        new Thread(this::startServer).start(); // Inicia o servidor (ouvinte)
        startConsole(); // Inicia o console (cliente)
    }

    private void startConsole() {
        try (BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println("Comandos: SEARCH <arquivo> (ex: SEARCH arquivo25) | SAIR");
            System.out.print(nodeId + "> ");
            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) break;

                if (userInput.toUpperCase().startsWith("SEARCH ")) {
                    String[] parts = userInput.split(" ");
                    if (parts.length == 2) {
                        String file = parts[1];
                        // Formato: "SEARCH;ARQUIVO;ID_ORIGEM;PORTA_ORIGEM"
                        // A porta de origem é usada para rotear a resposta "FOUND"
                        String payload = "SEARCH;" + file + ";" + this.nodeId + ";" + this.port;
                        processMessage(payload);
                    } else {
                        log("Formato inválido.");// [cite: 284]
                    }
                } else {
                    log("Comando desconhecido.");
                }
                System.out.print(nodeId + "> ");
            }
        } catch (Exception e) {
            log("Erro no console: " + e.getMessage());
        }
    }

    private void startServer() {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new NodeHandler(clientSocket, this)).start();
            }
        } catch (Exception e) {
            log("ERRO no Servidor: " + e.getMessage());
        }
    }

    /**
     * Lógica principal: processa uma mensagem de busca.
     * Verifica se o arquivo pertence a este nó ou se deve ser encaminhado.
     */
    public void processMessage(String payload) {
        try {
            String[] parts = payload.split(";");
            if (parts.length < 4 || !parts[0].equals("SEARCH")) {
                log("Mensagem mal formatada recebida: " + payload);
                return;
            }
            String file = parts[1];
            String originId = parts[2];
            int originPort = Integer.parseInt(parts[3]);

            if (isResponsible(file)) {
                log("ARQUIVO ENCONTRADO! '" + file + "' está neste nó (" + nodeId + ").");
                log("(Busca originada por: " + originId + ")");
                // Envia a resposta de volta para a ORIGEM
                String response = "FOUND;" + file + ";" + this.nodeId;
                sendSecureMessage(originPort, response);
            } else {
                // Se não é, encaminha para o sucessor
                log("Arquivo '" + file + "' não está aqui. Encaminhando para " + successorPort + "...");
                sendSecureMessage(successorPort, payload); // Encaminha a mensagem original
            }
        } catch (Exception e) {
            log("Erro ao processar mensagem: " + e.getMessage());
        }
    }

    /**
     * Encaminha a mensagem (payload) para um nó de forma segura.
     */
    public void sendSecureMessage(int destinationPort, String plainPayload) {
        log("Enviando (seguro): " + plainPayload + " para " + destinationPort);
        try (
                Socket socket = new Socket(successorHost, destinationPort);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            byte[] data = plainPayload.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedData = SecurityUtils.encrypt(SHARED_SECRET_KEY, data);// [cite: 287]
            byte[] hmac = SecurityUtils.calculateHmac(SHARED_SECRET_KEY, encryptedData);// [cite: 288]

            String hmacHex = ConverterUtils.bytes2Hex(hmac);
            String encryptedHex = ConverterUtils.bytes2Hex(encryptedData);
            out.println(hmacHex + "::" + encryptedHex);

        } catch (Exception e) {
            log("ERRO ao encaminhar para " + destinationPort + ": " + e.getMessage());
        }
    }

    private boolean isResponsible(String file) {
        try {
            int idNum = Integer.parseInt(nodeId.replace("P", ""));
            int fileNum = Integer.parseInt(file.replaceAll("(?i)arquivo", ""));
            // Define o intervalo de responsabilidade [cite: 273-278]
            int min = (idNum * 10) + 1;
            int max = (idNum * 10) + 10;
            return (fileNum >= min && fileNum <= max);
        } catch (NumberFormatException e) {
            log("Formato de arquivo ou ID inválido: " + file + " / " + nodeId);
            return false;
        }
    }

    public void log(String message) {
        // [cite: 285]
        System.out.println("[" + nodeId + " | " + java.time.LocalTime.now() + "] " + message);
    }
}