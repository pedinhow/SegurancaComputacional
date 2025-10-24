package q3;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Representa um único Processo (Nó) na topologia em Anel (Questão 3).
 * - Cada nó ouve em sua própria porta (Servidor).
 * - Cada nó conhece seu sucessor (Cliente).
 * - Encaminha buscas até encontrar o nó responsável.
 * - Implementa segurança (Cifra + HMAC) [cite: 738-740].
 * - Registra logs de mensagens.
 */
public class RingNode {

    private final String myId;        // ex: "P0"
    private final int myPort;
    private final String successorHost = "localhost";
    private final int successorPort;

    // Chave secreta COMPARTILHADA (todos os nós devem ter a mesma)
    public static final byte[] CHAVE_SECRETA =
            "chave-secreta-do-anel-p2p".getBytes(StandardCharsets.UTF_8);

    // Para testar a falha de segurança (Nó P7 ou chave errada)
    // public static final byte[] CHAVE_SECRETA =
    //    "chave-errada-do-intruso".getBytes(StandardCharsets.UTF_8);

    public RingNode(String myId, int myPort, int successorPort) {
        this.myId = myId;
        this.myPort = myPort;
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
            int porta = Integer.parseInt(args[1]);
            int portaSucessor = Integer.parseInt(args[2]);

            RingNode node = new RingNode(id, porta, portaSucessor);
            node.iniciar();

        } catch (Exception e) {
            System.err.println("Erro ao iniciar nó: " + e.getMessage());
        }
    }

    /**
     * Inicia as duas threads principais:
     * 1. O servidor (para ouvir outros nós).
     * 2. O console (para ouvir o usuário).
     */
    public void iniciar() {
        log("Nó " + myId + " iniciado. Ouvindo na porta " + myPort + ". Sucessor na porta " + successorPort);

        // 1. Inicia o servidor em uma nova thread
        Thread serverThread = new Thread(this::iniciarServidor);
        serverThread.start();

        // 2. Inicia o listener do console na thread principal
        iniciarConsole();
    }

    /**
     * Ouve o console para comandos do usuário (ex: BUSCAR arquivoX).
     */
    private void iniciarConsole() {
        try (BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.println("Comandos: BUSCAR <arquivo> (ex: BUSCAR arquivo25) | SAIR");
            System.out.print(myId + "> ");

            String userInput;
            while ((userInput = consoleIn.readLine()) != null) {
                if ("SAIR".equalsIgnoreCase(userInput)) break;

                if (userInput.toUpperCase().startsWith("BUSCAR ")) {
                    String[] partes = userInput.split(" ");
                    if (partes.length == 2) {
                        String arquivo = partes[1]; // ex: "arquivo25"
                        // Cria a mensagem de busca
                        String payload = "SEARCH;" + myId + ";" + arquivo;
                        // Processa a mensagem (verifica se é dele ou encaminha)
                        processarMensagem(payload);
                    } else {
                        log("Formato inválido.");
                    }
                } else {
                    log("Comando desconhecido.");
                }
                System.out.print(myId + "> ");
            }
        } catch (Exception e) {
            log("Erro no console: " + e.getMessage());
        }
    }

    /**
     * Inicia o ServerSocket e aguarda conexões de outros nós.
     */
    private void iniciarServidor() {
        try (ServerSocket serverSocket = new ServerSocket(myPort)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                // Cada conexão é tratada em uma nova thread
                Thread clientThread = new Thread(new NodeHandler(clientSocket, this));
                clientThread.start();
            }
        } catch (Exception e) {
            log("ERRO no Servidor: " + e.getMessage());
        }
    }

    /**
     * Lógica principal: processa uma mensagem de busca.
     * Verifica se o arquivo pertence a este nó ou se deve ser encaminhado.
     */
    public void processarMensagem(String payload) {
        try {
            String[] partes = payload.split(";");
            if (partes.length < 3 || !partes[0].equals("SEARCH")) {
                log("Mensagem mal formatada recebida: " + payload);
                return;
            }

            String origemId = partes[1];
            String arquivo = partes[2];

            if (isResponsavel(arquivo)) {
                // Se é responsável, a busca termina aqui.
                log("ARQUIVO ENCONTRADO! '" + arquivo + "' está neste nó (" + myId + ").");
                log("(Busca originada por: " + origemId + ")");
            } else {
                // Se não é, encaminha para o sucessor
                log("Arquivo '" + arquivo + "' não está aqui. Encaminhando para " + successorPort + "...");
                encaminharMensagem(payload);
            }
        } catch (Exception e) {
            log("Erro ao processar mensagem: " + e.getMessage());
        }
    }

    /**
     * Encaminha a mensagem (payload) para o nó sucessor.
     * Age como um cliente.
     */
    private void encaminharMensagem(String payloadPlano) {
        // Envia de forma segura (Cifra + HMAC)
        try (
                Socket socket = new Socket(successorHost, successorPort);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            log("Enviando (seguro): " + payloadPlano + " para " + successorPort);

            // 1. Cifrar
            byte[] dadosCifrados = SecurityUtils.cifrar(CHAVE_SECRETA,
                    payloadPlano.getBytes(StandardCharsets.UTF_8));

            // 2. Calcular HMAC
            byte[] hmac = SecurityUtils.calcularHmac(CHAVE_SECRETA, dadosCifrados);

            // 3. Enviar
            String hmacHex = ConverterUtils.bytes2Hex(hmac);
            String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);
            out.println(hmacHex + "::" + cifraHex);

        } catch (Exception e) {
            log("ERRO ao encaminhar para " + successorPort + ": " + e.getMessage());
        }
    }

    /**
     * Verifica se o arquivo (ex: "arquivo25") pertence a este nó.
     * [cite: 725-730]
     */
    private boolean isResponsavel(String arquivo) {
        try {
            // Remove "P" do ID (ex: "P0" -> 0)
            int idNum = Integer.parseInt(myId.replace("P", ""));
            // Remove "arquivo" do nome (ex: "arquivo25" -> 25)
            int fileNum = Integer.parseInt(arquivo.replaceAll("(?i)arquivo", ""));

            // Define o intervalo de responsabilidade [cite: 725-730]
            int min = (idNum * 10) + 1;
            int max = (idNum * 10) + 10;

            return (fileNum >= min && fileNum <= max);

        } catch (NumberFormatException e) {
            log("Formato de arquivo ou ID inválido: " + arquivo + " / " + myId);
            return false;
        }
    }

    /**
     * Helper para imprimir logs com o ID do nó.
     */
    public void log(String mensagem) {
        System.out.println("[" + myId + " | " + java.time.LocalTime.now() + "] " + mensagem);
    }
}

/**
 * Thread para lidar com uma conexão *recebida* de outro nó.
 * Age como a parte "Servidor".
 */
class NodeHandler implements Runnable {

    private final Socket socket;
    private final RingNode node; // Referência de volta ao nó principal

    public NodeHandler(Socket socket, RingNode node) {
        this.socket = socket;
        this.node = node;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))
        ) {
            String linhaRecebida = in.readLine();
            if (linhaRecebida == null) return;

            node.log("Mensagem recebida (bruta): " + linhaRecebida);

            // 1. Decodificar
            String[] partes = linhaRecebida.split("::");
            if (partes.length != 2) {
                node.log("ERRO: Formato de segurança inválido. Descartando.");
                return;
            }

            byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
            byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

            // 2. Verificar HMAC (Teste de Falha)
            //    [cite: 742, 743, 744, 745]
            boolean hmacValido = SecurityUtils.checarHmac(RingNode.CHAVE_SECRETA, dadosCifrados, hmacRecebido);
            if (!hmacValido) {
                node.log("FALHA DE SEGURANÇA: HMAC inválido (chave errada?). Mensagem descartada.");
                // Requisito: Descartar a mensagem [cite: 743, 745]
                return;
            }

            node.log("HMAC verificado com sucesso.");

            // 3. Decifrar
            byte[] dadosDecifrados = SecurityUtils.decifrar(RingNode.CHAVE_SECRETA, dadosCifrados);
            String payload = new String(dadosDecifrados, StandardCharsets.UTF_8);

            node.log("Mensagem decifrada: " + payload);

            // 4. Processar (Verificar se é meu ou encaminhar)
            node.processarMensagem(payload);

        } catch (Exception e) {
            node.log("ERRO no Handler: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }
}
