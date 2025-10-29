package q1;

import common.ConverterUtils;
import common.SecurityUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Classe interna para gerenciar a comunicação com cada cliente.
 */
class ClientHandler implements Runnable {

    private final Socket socket;
    private final Map<String, String> mapaDns;
    private final List<PrintWriter> clientesRequisitantes;
    private PrintWriter out;

    public ClientHandler(Socket socket, Map<String, String> mapaDns, List<PrintWriter> clientesRequisitantes) {
        this.socket = socket;
        this.mapaDns = mapaDns;
        this.clientesRequisitantes = clientesRequisitantes;
    }

    @Override
    public void run() {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)
        ) {
            this.out = out;
            String linhaRecebida;

            while ((linhaRecebida = in.readLine()) != null) {
                System.out.println("\n[Handler] Mensagem recebida (bruta): " + linhaRecebida);

                try {
                    // 1. Decodificar a mensagem (formato: hmacHex::cifraHex)
                    String[] partes = linhaRecebida.split("::");
                    if (partes.length != 2) {
                        System.err.println("[Handler] ERRO: Formato da mensagem inválido. Descartando.");
                        continue;
                    }

                    byte[] hmacRecebido = ConverterUtils.hex2Bytes(partes[0]);
                    byte[] dadosCifrados = ConverterUtils.hex2Bytes(partes[1]);

                    // 2. Verificar HMAC (Integridade e Autenticidade)
                    //    Se a chave estiver errada, a verificação falha (Teste de Falha)
                    boolean hmacValido = SecurityUtils.checarHmac(MiniDNSServer.CHAVE_SECRETA, dadosCifrados, hmacRecebido);

                    if (!hmacValido) {
                        System.err.println("[Handler] FALHA DE SEGURANÇA: HMAC inválido (chave errada?). Mensagem descartada.");
                        // Requisito: O servidor deve descartar mensagens com hmac inválido
                        continue;
                    }

                    System.out.println("[Handler] HMAC verificado com sucesso (Autêntico e Íntegro).");

                    // 3. Decifrar (Confidencialidade)
                    byte[] dadosDecifrados = SecurityUtils.decifrar(MiniDNSServer.CHAVE_SECRETA, dadosCifrados);
                    String comando = new String(dadosDecifrados, StandardCharsets.UTF_8);
                    System.out.println("[Handler] Comando decifrado: " + comando);

                    // 4. Processar o comando
                    String resposta = processarComando(comando);

                    // 5. Enviar resposta segura (Cifrar e Assinar com HMAC)
                    enviarMensagemSegura(resposta, MiniDNSServer.CHAVE_SECRETA);

                } catch (Exception e) {
                    System.err.println("[Handler] Erro ao processar mensagem: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            // Silencioso se for um fechamento normal de socket
        } finally {
            // Remove o cliente da lista de notificação se ele se desconectar
            if (out != null) {
                clientesRequisitantes.remove(out);
                System.out.println("[Handler] Cliente desconectado.");
            }
            try {
                socket.close();
            } catch (Exception e) { /* ignora */ }
        }
    }

    /**
     * Processa o comando em texto plano recebido do cliente.
     */
    private String processarComando(String comando) {
        String[] partes = comando.split(" ");
        String operacao = partes[0].toUpperCase();

        switch (operacao) {
            case "SUBSCRIBE":
                // Cliente requisitante se registra para receber atualizações
                if (!clientesRequisitantes.contains(this.out)) {
                    clientesRequisitantes.add(this.out);
                    System.out.println("[Handler] Cliente requisitante registrado para atualizações.");
                }
                return "OK;Registrado para atualizações.";

            case "QUERY":
                if (partes.length < 2) return "ERROR;Formato inválido. Use: RESOLVE <nome>";
                String nome = partes[1];
                String ip = mapaDns.get(nome);
                return (ip != null) ? "OK;" + nome + " -> " + ip : "ERROR;Nome não encontrado: " + nome;

            case "UPDATE":
                if (partes.length < 3) return "ERROR;Formato inválido. Use: UPDATE <nome> <novo_ip>";

                String nomeAtualizar = partes[1];
                String novoIp = partes[2];

                // Requisito: Apenas servidores 1, 4 e 9 podem ser atualizados
                if (!nomeAtualizar.equals("servidor1") &&
                        !nomeAtualizar.equals("servidor4") &&
                        !nomeAtualizar.equals("servidor9")) {
                    return "ERROR;Permissão negada para atualizar " + nomeAtualizar;
                }

                mapaDns.put(nomeAtualizar, novoIp);
                System.out.println("[Handler] BINDING DINÂMICO: " + nomeAtualizar + " atualizado para " + novoIp);

                // Notificar todos os clientes requisitantes
                notificarClientes(nomeAtualizar, novoIp);

                return "OK;Atualizado com sucesso: " + nomeAtualizar + " -> " + novoIp;

            default:
                return "ERROR;Comando desconhecido: " + operacao;
        }
    }

    /**
     * Envia uma mensagem segura (cifrada + HMAC) para o cliente.
     */
    private void enviarMensagemSegura(String mensagemPlana, byte[] chave) throws Exception {
        System.out.println("[Handler] Enviando resposta (plana): " + mensagemPlana);

        // 1. Cifrar (Confidencialidade)
        byte[] dadosCifrados = SecurityUtils.cifrar(chave,
                mensagemPlana.getBytes(StandardCharsets.UTF_8));

        // 2. Calcular HMAC (Autenticidade e Integridade)
        byte[] hmac = SecurityUtils.calcularHmac(chave, dadosCifrados);

        // 3. Converter para Hex e enviar no formato: hmacHex::cifraHex
        String hmacHex = ConverterUtils.bytes2Hex(hmac);
        String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);

        String mensagemSegura = hmacHex + "::" + cifraHex;
        this.out.println(mensagemSegura);
    }

    /**
     * Notifica todos os clientes requisitantes sobre uma atualização (Binding Dinâmico).
     */
    private void notificarClientes(String nome, String novoIp) {
        String mensagem = "UPDATED;" + nome + ";" + novoIp;
        System.out.println("[Handler] Notificando " + clientesRequisitantes.size() + " clientes...");

        synchronized (clientesRequisitantes) {
            for (PrintWriter clienteOut : clientesRequisitantes) {
                try {
                    // Envia a notificação de forma segura
                    byte[] dadosCifrados = SecurityUtils.cifrar(MiniDNSServer.CHAVE_SECRETA,
                            mensagem.getBytes(StandardCharsets.UTF_8));
                    byte[] hmac = SecurityUtils.calcularHmac(MiniDNSServer.CHAVE_SECRETA, dadosCifrados);

                    String hmacHex = ConverterUtils.bytes2Hex(hmac);
                    String cifraHex = ConverterUtils.bytes2Hex(dadosCifrados);

                    clienteOut.println(hmacHex + "::" + cifraHex);
                } catch (Exception e) {
                    System.err.println("[Handler] Erro ao notificar cliente: " + e.getMessage());
                }
            }
        }
    }
}
